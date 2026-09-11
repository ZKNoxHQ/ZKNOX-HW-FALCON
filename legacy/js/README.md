# Falcon-1024 v0.6.0 full-chain test kit

End-to-end validation of the Ledger Nano S+ Falcon-1024 implementation:

```
KEYGEN → GET_PK → KEYGEN_EXPAND → SIGN → verify_raw (JS)
```

## Pre-requisites
- Device flashed with Falcon-1024 v0.6.0 (Falcon-only build, with FALCON_KEYGEN_EXPAND=0x34)
- Device configured with BIP-39 mnemonic = "yellow ×12", no passphrase
- Device unlocked, Falcon app open
- Node.js >= 18 (for native crypto.shake256 support)

## Setup
```bash
npm install @ledgerhq/hw-transport-node-hid
```

## Run

### Quick compliance test (keygen + wire only, no sign)
```bash
node falcon1024-compliance-simple.js
```

Tests that the device's pk and wire match committed references for yellow×12.

### Full closed-loop test (keygen + sign + verify)
```bash
node falcon1024-full-chain.js [<message>]
```

Default message: `"Hello Falcon"`. Drives the full state machine and verifies the signature in JS.

## Files in this kit

| File                                | Purpose                                       |
|-------------------------------------|-----------------------------------------------|
| `falcon1024-ledger-keygen-expand.js`| APDU client for KEYGEN + KEYGEN_EXPAND        |
| `falcon1024-ledger-sign.js`         | APDU client for SIGN (12-step state machine) |
| `falcon1024-verify.js`              | Pure-JS Falcon-1024 verify_raw + hash_to_point |
| `falcon1024-compliance-simple.js`   | Quick compliance test runner                  |
| `falcon1024-full-chain.js`          | Full keygen + sign + verify orchestrator      |
| `falcon1024_yellow12_pk.bin`        | Reference public key (2 KB)                   |
| `falcon1024_yellow12_wire.bin`      | Reference wire blob (123 KB)                  |

## Reference values (yellow×12 mnemonic, no passphrase)

```
pk SHA-256:    abda0932325ead2b390ba6542d6ff45b02e03b2ffdafd338f39667dc152a40d3
wire SHA-256:  855edeedfacc2b4b56f6b5f5b688bf8b5fed4d7f02984633aeb88fdd48efe3d4
```

## Validation chain

The JS `verify_raw` and `hash_to_point` are validated byte-for-byte against
the Falcon reference implementation in C (test_falcon.c). On a known-good
trio (h, hm, sig) produced by `Zf(sign_tree)`:

- JS `hashToPoint(nonce, msg)` == C `Zf(hash_to_point_vartime)`
- JS `verifyRaw(hm, sig, h)` == C `Zf(verify_raw)` (after `to_ntt_monty(h)`)

The L2 norm bound for n=1024 is `(7085 * 12289) >> 0 = 87,067,565`.

## Expected timing on Nano S+

| Step                          | Time    |
|-------------------------------|---------|
| FALCON_KEYGEN + GET_PK        | ~17.8 s |
| FALCON_KEYGEN_EXPAND          | ~14.9 s |
| FALCON_SIGN (full state machine) | ~8 s |
| JS verify_raw                 | ~20 ms  |
