// crypto.hpp
//
// Crypto primitives matching protocol.md section 1 and the pseudocode in
// sections 3 (X3DH) and 4 (Double Ratchet), built on libsodium.
//
// libsodium 1.0.18 (the version available in this lab's base images) does
// not ship crypto_kdf_hkdf_sha256_*, so HKDF-SHA256 (RFC 5869) is
// implemented here directly on top of crypto_auth_hmacsha256.
//
// ASSUMPTION flagged for the report: protocol.md does not give the exact
// byte layout of `serialize(header)` used as AEAD associated data in
// ratchet_encrypt/ratchet_decrypt. We assume it is the compact JSON
// encoding of the header object with keys in declaration order
// (dh, pn, n[, init]), i.e. exactly what json_mini::dump() produces for a
// json::Value built the same way the client would build it. This matches
// the only reasonable implementation of a Go struct marshalled with
// encoding/json using the field order in protocol.md section 2.3, but it
// must be confirmed against a real capture (see README.md) before relying
// on attack2 to interoperate with the provided binary.

#pragma once
#include <sodium.h>
#include <string>
#include <vector>
#include <array>
#include <cstring>
#include <stdexcept>
#include "json_mini.hpp"

namespace crypto {

using Bytes = std::vector<uint8_t>;

inline Bytes fromB64(const std::string& b64) {
    Bytes out(b64.size()); // upper bound
    size_t outLen = 0;
    if (sodium_base642bin(out.data(), out.size(), b64.c_str(), b64.size(),
                           nullptr, &outLen, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("base64 decode failed");
    }
    out.resize(outLen);
    return out;
}

inline std::string toB64(const Bytes& bin) {
    size_t b64Len = sodium_base64_ENCODED_LEN(bin.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string out(b64Len, '\0');
    sodium_bin2base64(&out[0], b64Len, bin.data(), bin.size(), sodium_base64_VARIANT_ORIGINAL);
    out.resize(strlen(out.c_str())); // trim trailing NUL padding from the API
    return out;
}

inline Bytes concat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

inline Bytes fromStr(const std::string& s) { return Bytes(s.begin(), s.end()); }

// ---------------- HMAC-SHA256 / HKDF-SHA256 (RFC 5869) ----------------

inline Bytes hmacSha256(const Bytes& key, const Bytes& msg) {
    // libsodium's crypto_auth_hmacsha256 requires a fixed 32-byte key; HKDF
    // needs arbitrary-length keys for the extract step, so hash down first
    // per RFC 2104 when longer, and use crypto_auth_hmacsha256_* streaming
    // state with crypto_auth_hmacsha256_init which *does* take arbitrary
    // key lengths.
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    crypto_auth_hmacsha256_update(&st, msg.data(), msg.size());
    Bytes out(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_final(&st, out.data());
    return out;
}

inline Bytes hkdfExtract(const Bytes& salt, const Bytes& ikm) {
    return hmacSha256(salt, ikm);
}

inline Bytes hkdfExpand(const Bytes& prk, const Bytes& info, size_t length) {
    Bytes t, okm;
    uint8_t counter = 1;
    while (okm.size() < length) {
        Bytes input = t;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        t = hmacSha256(prk, input);
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(length);
    return okm;
}

inline Bytes hkdfSha256(const Bytes& salt, const Bytes& ikm, const Bytes& info, size_t length) {
    return hkdfExpand(hkdfExtract(salt, ikm), info, length);
}

// ---------------- X25519 ----------------

struct X25519KeyPair {
    Bytes pub = Bytes(crypto_scalarmult_curve25519_BYTES);
    Bytes priv = Bytes(crypto_scalarmult_curve25519_BYTES);
};

inline X25519KeyPair x25519Generate() {
    X25519KeyPair kp;
    randombytes_buf(kp.priv.data(), kp.priv.size());
    crypto_scalarmult_curve25519_base(kp.pub.data(), kp.priv.data());
    return kp;
}

inline Bytes x25519(const Bytes& myPriv, const Bytes& theirPub) {
    Bytes out(crypto_scalarmult_curve25519_BYTES);
    if (crypto_scalarmult_curve25519(out.data(), myPriv.data(), theirPub.data()) != 0) {
        throw std::runtime_error("x25519: low-order / invalid point");
    }
    return out;
}

// ---------------- Ed25519 ----------------

struct Ed25519KeyPair {
    Bytes pub = Bytes(crypto_sign_ed25519_PUBLICKEYBYTES);
    Bytes priv = Bytes(crypto_sign_ed25519_SECRETKEYBYTES);
};

inline Ed25519KeyPair ed25519Generate() {
    Ed25519KeyPair kp;
    crypto_sign_ed25519_keypair(kp.pub.data(), kp.priv.data());
    return kp;
}

inline Bytes ed25519Sign(const Bytes& priv, const Bytes& msg) {
    Bytes sig(crypto_sign_ed25519_BYTES);
    unsigned long long sigLen = 0;
    crypto_sign_ed25519_detached(sig.data(), &sigLen, msg.data(), msg.size(), priv.data());
    sig.resize(sigLen);
    return sig;
}

inline bool ed25519Verify(const Bytes& pub, const Bytes& msg, const Bytes& sig) {
    return crypto_sign_ed25519_verify_detached(sig.data(), msg.data(), msg.size(), pub.data()) == 0;
}

// ---------------- ChaCha20-Poly1305 (IETF, 96-bit nonce) ----------------
// protocol.md 4.3: "Each message key mk is used exactly once, so a fixed
// nonce is safe." -> all-zero 12-byte nonce, matching ZERO_NONCE.

inline Bytes chachaEncrypt(const Bytes& key, const Bytes& plaintext, const Bytes& ad) {
    Bytes nonce(crypto_aead_chacha20poly1305_IETF_NPUBBYTES, 0);
    Bytes ct(plaintext.size() + crypto_aead_chacha20poly1305_IETF_ABYTES);
    unsigned long long ctLen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ct.data(), &ctLen, plaintext.data(), plaintext.size(),
        ad.data(), ad.size(), nullptr, nonce.data(), key.data());
    ct.resize(ctLen);
    return ct;
}

// Returns false if authentication failed (this is the hook attack0/attack2
// use to show whether a tampered/forged frame is accepted).
inline bool chachaDecrypt(const Bytes& key, const Bytes& ct, const Bytes& ad, Bytes& outPlaintext) {
    Bytes nonce(crypto_aead_chacha20poly1305_IETF_NPUBBYTES, 0);
    outPlaintext.resize(ct.size());
    unsigned long long ptLen = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        outPlaintext.data(), &ptLen, nullptr, ct.data(), ct.size(),
        ad.data(), ad.size(), nonce.data(), key.data());
    if (rc != 0) return false;
    outPlaintext.resize(ptLen);
    return true;
}

// ---------------- Double Ratchet KDFs (protocol.md 4.1) ----------------

struct RootStep { Bytes rk; Bytes ck; };

inline RootStep kdfRk(const Bytes& rk, const Bytes& dhOut) {
    Bytes out = hkdfSha256(rk, dhOut, fromStr("AS3_ROOT"), 64);
    RootStep r;
    r.rk.assign(out.begin(), out.begin() + 32);
    r.ck.assign(out.begin() + 32, out.end());
    return r;
}

struct ChainStep { Bytes mk; Bytes ck; };

inline ChainStep kdfCk(const Bytes& ck) {
    ChainStep r;
    r.mk = hmacSha256(ck, fromStr("\x01"));
    r.ck = hmacSha256(ck, fromStr("\x02"));
    return r;
}

static const char* INFO_X3DH = "AS3_X3DH";

} // namespace crypto
