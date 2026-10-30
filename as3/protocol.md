# AS3 Messaging Protocol — Specification

This document describes the messaging protocol used by the lab server and
clients. Use it together with the packet captures and the client/server logs
while you investigate the implementation.

The protocol is a X3DH key agreement followed by a Double Ratchet session, in
the style of the Signal specifications:

- The Double Ratchet Algorithm — <https://signal.org/docs/specifications/doubleratchet/>
- The X3DH Key Agreement Protocol — <https://signal.org/docs/specifications/x3dh/>

---

## 1. Cryptographic primitives

| Role | Primitive |
|------|-----------|
| Diffie-Hellman | X25519 (Curve25519) |
| Signed-prekey signature | Ed25519 |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| Authenticated encryption | ChaCha20-Poly1305 (IETF, 96-bit nonce) |

Each party owns:

- a long-term **identity key**: an Ed25519 signing key `IK_sig` and an X25519
  DH key `IK_dh`,
- a **signed prekey** `SPK` (X25519), signed by `IK_sig`,
- a set of **one-time prekeys** `OPK` (X25519), each with an integer id.

All key material on the wire is **base64 (standard, padded)**.

---

## 2. Wire format

### 2.1 Framing

The transport is TCP. Every request and response is a single JSON object
encoded on **one line, terminated by `\n`** (newline-delimited JSON). A frame
has a maximum size; longer lines are rejected.

Because the framing is plaintext JSON, you can read it directly in a capture:

```
tshark -i any -f "tcp port 9000" -T fields -e tcp.payload
```

### 2.2 Envelope

Every message is one envelope object. `type` selects the operation; the other
fields are present only when relevant.

```jsonc
{
  "type":   "register" | "publish" | "fetch_bundle" | "send" | "poll"
          |  "ok" | "err" | "bundle" | "frames",
  "user":   "<username>",          // subject of the request
  "bundle": { Bundle },            // publish request / fetch_bundle response
  "opks":   [ OPKEntry, ... ],     // publish request
  "frame":  { Frame },             // send request
  "frames": [ Frame, ... ],        // poll response
  "ok":     true,                  // success responses
  "err":    "<reason>",            // error responses
  "count":  <int>                  // one-time prekeys remaining (informational)
}
```

### 2.3 Types

**Bundle** — a user's published key material (returned by `fetch_bundle`):

```jsonc
{
  "user":    "bob",
  "ik_sig":  "<b64 Ed25519 identity verify key>",
  "ik_dh":   "<b64 X25519 identity DH key>",
  "spk":     "<b64 X25519 signed prekey>",
  "spk_sig": "<b64 Ed25519 signature over `spk`>",
  "opk":     "<b64 X25519 one-time prekey>",   // "" if none available
  "opk_id":  7                                  // 0 if none
}
```

**OPKEntry** — one one-time prekey being published:

```jsonc
{ "id": 7, "pub": "<b64 X25519 public key>" }
```

**Frame** — one end-to-end encrypted message. The server relays it without
reading the plaintext:

```jsonc
{
  "from": "alice",
  "to":   "bob",
  "header": {
    "dh": "<b64 sender ratchet public key>",
    "pn": 0,                 // length of sender's previous sending chain
    "n":  1,                 // message number in sender's current chain
    "init": {                // PRESENT ONLY ON THE FIRST MESSAGE of a session
      "ik_sig": "<b64>",     // initiator identity verify key
      "ik_dh":  "<b64>",     // initiator identity DH key
      "ek":     "<b64>",     // initiator ephemeral key (X25519)
      "opk_id": 7            // which of the receiver's OPKs was used (0 = none)
    }
  },
  "ct": "<b64 ChaCha20-Poly1305 ciphertext>"
}
```

### 2.4 Operations

| Request | Response | Meaning |
|---------|----------|---------|
| `{"type":"register","user":"bob"}` | `{"type":"ok"}` | claim a username on this connection |
| `{"type":"publish","user":"bob","bundle":{…},"opks":[…]}` | `{"type":"ok","count":N}` | publish/replace identity + signed prekey, append one-time prekeys |
| `{"type":"fetch_bundle","user":"bob"}` | `{"type":"bundle","bundle":{…},"count":N}` | obtain a peer's bundle to start a session |
| `{"type":"send","frame":{…}}` | `{"type":"ok"}` | hand an encrypted frame to the server for delivery |
| `{"type":"poll","user":"bob"}` | `{"type":"frames","frames":[…]}` | collect queued frames addressed to you |

Delivery is pull-based: `send` queues a frame in the recipient's mailbox, and
the recipient retrieves it with `poll`.

---

## 3. X3DH key agreement

When Alice wants to message Bob for the first time she fetches Bob's bundle and
runs X3DH. The shared secret seeds the Double Ratchet.

```python
INFO_X3DH = b"AS3_X3DH"

def x3dh_initiate(my_ik_dh, my_ik_sig, bundle):
    # bundle = {ik_sig, ik_dh, spk, spk_sig, opk, opk_id}

    # Verify the signed prekey against the identity key before using it.
    assert ed25519_verify(bundle.ik_sig, bundle.spk, bundle.spk_sig)

    ek = x25519_generate()                       # fresh ephemeral key pair

    dh1 = x25519(my_ik_dh.priv, bundle.spk)      # DH(IK_A, SPK_B)
    dh2 = x25519(ek.priv,       bundle.ik_dh)    # DH(EK_A, IK_B)
    dh3 = x25519(ek.priv,       bundle.spk)      # DH(EK_A, SPK_B)

    ikm = b"\xFF" * 32 + dh1 + dh2 + dh3
    if bundle.opk != "":
        ikm += x25519(ek.priv, bundle.opk)       # DH(EK_A, OPK_B)

    sk = hkdf_sha256(salt=b"\x00"*32, ikm=ikm, info=INFO_X3DH, length=32)

    ad   = my_ik_dh.pub + bundle.ik_dh           # associated data for the session
    init = {"ik_sig": my_ik_sig.pub, "ik_dh": my_ik_dh.pub,
            "ek": ek.pub, "opk_id": bundle.opk_id}

    state = ratchet_init_sender(sk, bundle.spk, ad)
    return state, init                           # `init` travels in the first header


def x3dh_respond(my_ik_dh, my_spk, my_opk, init):
    dh1 = x25519(my_spk.priv,   init.ik_dh)      # mirror of DH1
    dh2 = x25519(my_ik_dh.priv, init.ek)         # mirror of DH2
    dh3 = x25519(my_spk.priv,   init.ek)         # mirror of DH3

    ikm = b"\xFF" * 32 + dh1 + dh2 + dh3
    if init.opk_id != 0:
        ikm += x25519(my_opk.priv, init.ek)      # mirror of DH4

    sk = hkdf_sha256(salt=b"\x00"*32, ikm=ikm, info=INFO_X3DH, length=32)
    ad = init.ik_dh + my_ik_dh.pub
    return ratchet_init_receiver(sk, my_spk, ad)
```

---

## 4. Double Ratchet

### 4.1 Key-derivation functions

```python
def kdf_rk(rk, dh_out):
    # root chain step -> (new root key, new chain key)
    out = hkdf_sha256(salt=rk, ikm=dh_out, info=b"AS3_ROOT", length=64)
    return out[:32], out[32:]

def kdf_ck(ck):
    # symmetric chain step -> (message key, next chain key)
    mk  = hmac_sha256(ck, b"\x01")
    nck = hmac_sha256(ck, b"\x02")
    return mk, nck
```

### 4.2 Session initialisation

```python
def ratchet_init_sender(sk, their_spk, ad):
    st = State(RK=sk, DHr=their_spk, AD=ad)
    st.DHs = x25519_generate()                       # our first ratchet key pair
    st.RK, st.CKs = kdf_rk(st.RK, x25519(st.DHs.priv, their_spk))
    return st

def ratchet_init_receiver(sk, my_spk, ad):
    # keep the signed-prekey pair as the initial ratchet key; the matching
    # DH-ratchet step happens when the first message arrives.
    return State(RK=sk, DHs=my_spk, DHr=None, AD=ad)
```

### 4.3 Encrypting a message

```python
MAX_SKIP = 1000          # upper bound on skipped message keys per step

def ratchet_encrypt(st, plaintext):
    mk, st.CKs = kdf_ck(st.CKs)                      # advance sending chain
    header = {
        "dh": st.DHs.pub,
        "pn": st.PN,                                 # previous sending-chain length
        "n":  st.Ns,                                 # this message's number
    }
    st.Ns += 1
    ad = st.AD + serialize(header)                   # bind the header
    ct = chacha20poly1305_encrypt(key=mk, nonce=ZERO_NONCE,
                                  plaintext=plaintext, ad=ad)
    return header, ct
```

Each message key `mk` is used exactly once, so a fixed nonce is safe.

### 4.4 Decrypting a message

```python
def ratchet_decrypt(st, header, ct):
    mk = try_skipped_keys(st, header)                # out-of-order delivery
    if mk is not None:
        return aead_decrypt(mk, ct, st.AD + serialize(header))

    if header["dh"] != st.DHr:                       # peer ratcheted
        skip_message_keys(st, header["pn"])          # finish current recv chain
        dh_ratchet(st, header)                       # step the DH ratchet
    skip_message_keys(st, header["n"])               # catch up to this message

    mk, st.CKr = kdf_ck(st.CKr)                       # advance receiving chain
    st.Nr += 1
    return aead_decrypt(mk, ct, st.AD + serialize(header))


def skip_message_keys(st, until):
    if until - st.Nr > MAX_SKIP:
        raise Error("too many skipped messages")
    if st.CKr is None:
        return
    while st.Nr < until:
        mk, st.CKr = kdf_ck(st.CKr)
        st.skipped[(st.DHr, st.Nr)] = mk              # store for later arrival
        st.Nr += 1


def dh_ratchet(st, header):
    st.PN  = st.Ns
    st.Ns  = 0
    st.Nr  = 0
    st.DHr = header["dh"]
    st.RK, st.CKr = kdf_rk(st.RK, x25519(st.DHs.priv, st.DHr))
    st.DHs = x25519_generate()                        # new sending ratchet key
    st.RK, st.CKs = kdf_rk(st.RK, x25519(st.DHs.priv, st.DHr))
```

---

## 5. Session lifecycle

1. A client **registers** a username, then **publishes** its bundle (identity
   key, signed prekey, and a batch of one-time prekeys).
2. To start a session, the initiator **fetches** the peer's bundle and runs
   `x3dh_initiate`. The resulting `init` block is carried in the header of the
   first message only.
3. The responder runs `x3dh_respond` the first time it sees an `init` block,
   then both sides exchange `Frame`s via `send` / `poll`.
4. Thereafter every message advances a symmetric chain; sending in the other
   direction performs a DH ratchet step (a new `header.dh`).

### One-time prekey (OPK) lifecycle

Each `fetch_bundle` hands out — and consumes — one of the target's one-time
prekeys; the `count` field reports how many remain. Once the inventory is empty
the server refuses `fetch_bundle`, so **no new session can be started** with that
user until they publish more prekeys (they replenish by publishing again). An
**already-established** session is unaffected and keeps exchanging messages: OPKs
are an X3DH-handshake resource, not a per-message one. (How quickly the inventory
drains, and whether fetching is authenticated or rate-limited, is worth examining.)

### Client state persistence

A client persists its private keys **and its live ratchet sessions** across
restarts. Consequences to keep in mind while testing:

- A client that exits and comes back **resumes** its sessions, so messages queued
  while it was offline decrypt on reconnect.
- The `init` block is sent **once per session** (the first message). A peer that
  still holds the session processes later messages with no `init`; a peer that has
  **lost** its session state cannot bootstrap from those later messages and must
  establish a new session (which needs an available OPK).

### Reading the logs

Each client logs the ratchet public key tail and counters per message, e.g.

```
sent -> bob  (dh=...19d3ef01, n=0, pn=0)
sent -> bob  (dh=...19d3ef01, n=1, pn=0)     # same dh  => symmetric-chain step
recv <- bob  (dh=...5d13e308, n=0, pn=0)     # new dh   => peer did a DH ratchet
sent -> bob  (dh=...ca95226b, n=0, pn=2)     # new dh   => we did a DH ratchet
```

Use these together with the captures to trace how keys evolve — and to judge
whether the implementation actually follows this specification.
