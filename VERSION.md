# ZKNOX-HW-FALCON — Falcon-512 flash variant — VERSION.md

## v0.2.0 — phase 2b (real flash sign)
- INS 0x63 P1=0x10 SIGN_ALL: full synchronous on-device sign in a single APDU
- INS 0x63 P1=0x06/0x08/0x09/0x91: FEED_MSG, FEED_NONCE_HOST, GEN_NONCE_DEVICE, GET_NONCE
- INS 0x64: chunked GET_SIG (1024 bytes int16 LE = 5 chunks)
- New struct `falcon512_flash_sign_ctx_t` (~24 KB) aliased onto `_falcon_sign_area`
- Helpers `dfs_feed`, `do_level0_enter`, `do_merge_right`, `do_after_right`,
  `do_merge_left`, `do_compute_s0_sqn`, `do_compute_s1_and_check` copied verbatim
  from streaming variant with `sctx` → `fctx` rename
- L0 read once from NVRAM[0..4096) at do_after_right time (vs streaming's
  double-feed via FEED_SWAP)
- Tree nodes consumed via `memcpy(ws, N_falcon_tree_512 + offset, len)` instead
  of `cx_outsourced_read_split` (NVRAM is in the same TCB as the seed; no
  encryption / no MAC needed)
- z0 + z1 preserved on-device in `fctx.z_pair_save[2*FN]` (8 KB) — replaces
  streaming roundtrip where host buffers them between s0 and s1
- BSS impact: fctx ~24 KB, fits in 32 KB `_falcon_sign_area`. NVRAM unchanged
  from phase 2a (41 985 bytes total)

## v0.1.0 — phase 2a (LDL expand to NVRAM, sign stub)
- INS 0x62 KEYGEN_EXPAND: real LDL walker, writes 40 960 B plaintext to NVRAM
- INS 0x63 SIGN: stub (returns 0x9000 without doing anything)
- INS 0x64 GET_SIG: stub (returns dummy bytes)
- INS 0x65 DUMP_NVM: chunked NVRAM dump for byte-for-byte cross-check vs streaming

## v0.0.1 — phase 1 (skeleton)
- INS 0x60 KEYGEN, 0x61 GET_PK working (calls `Zf(keygen)` + nvm_write of pk)
- INS 0x62 KEYGEN_EXPAND stub (writes deterministic test pattern to NVRAM)
- INS 0x63/0x64/0x65 stubs
