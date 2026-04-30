# Falcon-1024-only build (Dilithium stripped)

## What was removed

- `zknox/dilithium/` entire directory (Dilithium PQC implementation)
- `handler/zkn_magicbox.{c,h}` (Dilithium handlers + Keccak utility INS + ECDSA + hybrid sign hash)
- `handler/handler_hybrid_sign_userop.{c,h}` (hybrid Dilithium+ECDSA UserOp)
- INS codes: `KECCAK_HASH`, `KECCAK_PRNG`, `DUMMY`, `SAMPLE_IN_BALL`,
  `KEYGEN_DILITHIUM_CORE`, `KEYGEN_DILITHIUM`, `SIGN_DILITHIUM`,
  `VERIFY_DILITHIUM`, `GET_SIG_CHUNK`, `GET_PK_CHUNK`, `GET_MLDSA_SEED`,
  `ECDSA_SIGN_HASH`, `HYBRID_SIGN_HASH`, `HYBRID_SIGN_USEROP`
- `mldsa_seed[32]` from `g_zknox` struct
- The Dilithium branch of the union in `g_zknox`
  (`hash_ctx`, `buf`, `tr`, `pk`, `sig`)

## Kept

- All Falcon-1024 functionality (`FALCON_KEYGEN` 0x30, `FALCON_GET_PK` 0x31,
  `FALCON_SIGN` 0x33, `FALCON_KEYGEN_EXPAND` 0x34)
- Standard app handlers: `GET_VERSION`, `GET_APP_NAME`, `GET_PUBLIC_KEY`,
  `SIGN_TX`, `SIGN_TOKEN_TX`, `PROVIDE_TOKEN_INFO`
- BIP-32 SLIP-10 derivation in `zknox/keys/derive.c` (only `falcon_derive_seed`)

## Makefile changes you must apply

1. Remove all references to `zknox/dilithium/*.c` from your sources list.

2. Remove these from your sources:
   - `handler/zkn_magicbox.c`
   - `handler/handler_hybrid_sign_userop.c`

3. If you have a flag like `ETHDILITHIUM`, you can remove its usage
   (the build no longer reads it).

4. Make sure `handler/handler_falcon_keygen_expand.c` IS in your sources
   (it's the new handler).

A quick way to verify: `make 2>&1 | grep -E "dilithium|magicbox|hybrid"`
should return nothing.

## RAM impact

- `_falcon_sign_area` grew from 32000 to 32768 B (+768 B)
- `mldsa_seed[32]` removed (-32 B)
- All Dilithium globals (BSS) removed: should free a few KB
- Net BSS change: roughly **net negative** (we save more than we add),
  so the linker stack section error from v0.6.0 should be resolved.

## Validation

After flash:

```bash
node falcon1024-compliance-simple.js
```

Expected:
- pk SHA-256 = `abda0932325ead2b390ba6542d6ff45b02e03b2ffdafd338f39667dc152a40d3`
- wire SHA-256 = `855edeedfacc2b4b56f6b5f5b688bf8b5fed4d7f02984633aeb88fdd48efe3d4`

(both for mnemonic "yellow×12", no passphrase)
