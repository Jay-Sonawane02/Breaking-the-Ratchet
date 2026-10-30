# Attacks — build & run

Three C/C++ proof-of-concept programs against the AS3 lab described in
`protocol.md`: a header-tampering DoS MITM (`attack0`), a prekey-exhaustion
client (`attack1`), and a fake-key MITM server (`attack2`). All three speak
the wire protocol directly (newline-delimited JSON over TCP, protocol.md
section 2) — none of them use the official `/client` or `/server` binaries.

## Dependencies

- A C++17 compiler (g++ or clang++)
- `libsodium` (dev headers). On Debian/Ubuntu:

  ```bash
  sudo apt-get update && sudo apt-get install -y libsodium-dev
  ```

  Only `attack2` links against libsodium (it does real X25519 / Ed25519 /
  HKDF-SHA256 / ChaCha20-Poly1305). `attack0` and `attack1` only need
  sockets + JSON and have no crypto dependency.

## Build

```bash
cd attacks
make
```

This produces `attack0`, `attack1`, `attack2` in this directory. `common/`
holds the shared JSON (`json_mini.hpp`), socket (`netutil.hpp`), and crypto
(`crypto.hpp`) helpers used by `attack2`.

## Before every attack: reset state

Per the assignment handout ("Note: Before each attack clear the client
state."):

```bash
docker compose down            # wipes the server's in-memory state
docker volume rm as3state      # wipes both clients' persisted keys/sessions
# (or: docker compose down -v)
```

---

## attack0 — MITM header manipulation / resource exhaustion

Mallory sits between the server and Bob and rewrites the message counter
(`header.n`, optionally `header.pn`) in frames addressed to Bob before
forwarding them.

```bash
# Terminal 1 — real server
docker compose up as3_server

# Terminal 2 — Mallory, listening on 9100, relaying to the real server
./attack0 --listen-port 9100 --server-host as3_server --server-port 9000 \
          --gap-n 999 --victim bob
#  (run this on the same docker network, e.g. via
#   `docker run --rm --network as3net -v $PWD:/w -w /w <base-image> ./attack0 ...`
#   or build/run it directly on the host if as3_server's port is published)

# Terminal 3 — Bob, pointed at Mallory instead of the real server
docker compose run --rm bob --serve-addr <mallory_ip> --port 9100

# Terminal 4 — Alice, talking to the real server as usual
docker compose run --rm alice
```

Send a message from Alice to Bob and watch terminal 2: it logs every
tampered frame (`n <orig> -> 999`). Watch Bob's console for whether the
message is accepted, rejected, or causes a visible stall, and run
`docker stats as3_server bob` (or whichever container names `docker ps`
shows) in a fifth terminal while repeating the send, increasing `--gap-n`
up to and beyond 1000 (`MAX_SKIP` in protocol.md 4.3) to find the cliff.

Useful variants:

```bash
./attack0 --gap-n 1000            # exactly at MAX_SKIP
./attack0 --gap-n 1001            # just over -> should be rejected outright
./attack0 --gap-n 999 --gap-pn 0  # also force pn, in case pn is checked separately
```

Capture traffic alongside this to see the tampered bytes on the wire and
confirm whether Bob's AEAD check actually rejects the modified frame:

```bash
tshark -i any -f "tcp port 9100" -T fields -e tcp.payload
```

## attack1 — Prekey Pogo (one-time prekey exhaustion)

Mallory is an ordinary client — no special network position, same as
Alice. Run it after Bob has published his bundle and gone offline (per
the assignment's scenario), pointed at the real server:

```bash
# Terminal 1 — real server
docker compose up as3_server

# Terminal 2 — Bob publishes a bundle, then exits (simulating "offline")
docker compose run --rm bob
# ... use the menu to publish/replenish prekeys, then Ctrl+D / exit

# Terminal 3 — Mallory drains Bob's one-time prekeys without ever
# establishing a session or sending him a single message
./attack1 --server-host as3_server --server-port 9000 --as mallory --victim bob \
          --max-attempts 20

# Terminal 4 — Alice tries to start a session with Bob afterward
docker compose run --rm alice
```

`attack1` logs each consumed `opk_id` and the remaining count, and stops
when the server refuses `fetch_bundle` (OPK inventory exhausted). Confirm
in terminal 4 that Alice's own `fetch_bundle(bob)` now also fails/returns
no OPK, i.e. she lost the ability to start a *new* forward-secret session
with Bob until he reconnects and republishes (protocol.md, "One-time
prekey (OPK) lifecycle").

Default `OPK_COUNT` in `docker-compose.yml` is `5`, so `--max-attempts 10`
is already generous headroom to observe the cutover.

## attack2 — Malicious server / fake-key MITM

`attack2` is a **full replacement for `as3_server`**: it implements
`register` / `publish` / `fetch_bundle` / `send` / `poll` itself, and on
every `send` transparently decrypts with the Double Ratchet session it
holds toward the real sender, then re-encrypts with a *separate* session
it holds toward the real recipient (using forged identity keys it
generated for each victim) before forwarding.

```bash
# Terminal 1 — the EVIL server instead of as3_server
./attack2 --listen-port 9000

# Terminal 2 — Bob, pointed at the evil server
docker compose run --rm bob --serve-addr <attacker_ip> --port 9000

# Terminal 3 — Alice, pointed at the evil server
docker compose run --rm alice --serve-addr <attacker_ip> --port 9000
```

Have Bob publish his bundle first, then have Alice message `bob` and send
a line of chat; have Bob reply. Watch terminal 1: it logs

- `forging a fresh identity to impersonate '<user>'` the first time it
  needs to hand out or present a fake identity for that user,
- `*** RECOVERED PLAINTEXT ***` lines showing the exact chat text it
  decrypted in both directions,

while Alice and Bob's own consoles show a completely ordinary-looking
conversation — neither one has any error, because each individually ran a
cryptographically valid X3DH + Double Ratchet session; they just each
ran it with the attacker instead of with each other.

This was validated end-to-end against a from-scratch Python
reimplementation of protocol.md's pseudocode (`cryptography` library)
standing in for the real clients, confirming: the bundle Alice fetches for
"bob" uses a different identity key than Bob's real one; the `init` block
Bob receives claiming to be from "alice" uses a different identity key
than Alice's real one; and both Alice and Bob each independently and
successfully decrypt messages that only ever touched the attacker's
re-encryption, never the other party's real key material.

### Important caveat — verify against the real binary

protocol.md does not specify the exact byte layout of
`serialize(header)` used as the AEAD associated data in `ratchet_encrypt`
/ `ratchet_decrypt` (section 4.3–4.4). `common/crypto.hpp` and
`attack2.cpp` assume it is compact JSON with keys in the declared order
`dh, pn, n[, init]` — the natural output of marshalling a Go struct with
fields in that order, and what our own internal round-trip test
confirms is *self-consistent*. But attack2's interoperability with the
**real** `s4ch1n/as3` client binaries depends on this assumption matching
their actual implementation. Before relying on results against the real
lab:

1. Capture a real Alice→Bob exchange:
   `tshark -i any -f "tcp port 9000" -T fields -e tcp.payload`
2. Compare the captured header bytes against what `json::dump()` in
   `common/json_mini.hpp` would produce for the same field values.
3. If they differ (field order, spacing, extra fields), adjust
   `headerJson()` / `headerAD()` in `attack2.cpp` to match, rebuild, and
   re-run.

If, after that check, the real binaries still reject every forged frame,
that is itself a reportable result: it means header/AD construction is
not the assumed format, and the report should say so explicitly rather
than claim success.

## Generative AI disclosure

See the report's Generative AI appendix for the prompts used while
building these PoCs and how each one's output was verified (smoke tests
and the end-to-end simulation referenced above).
