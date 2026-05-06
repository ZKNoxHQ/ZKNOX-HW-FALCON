# ZKNOX-HW-FALCON — Falcon-512 flash variant — DECISIONS.md

## ADR-2b-1: Single-APDU sign vs streaming-protocol mirror

**Context.** The streaming Falcon-512 sign uses 6+ APDUs because the host
stores the encrypted LDL tree off-device, sends nodes via `FEED_TREE_STREAM`,
buffers `z1` between right-subtree DFS and L0_after_right, and re-feeds
`z0+z1` separately for s0 and s1. In the flash variant, the tree is on-device
in NVRAM — none of these roundtrips serve a purpose.

**Options considered.**
1. **Mirror the streaming state machine 1:1**, replacing host wire reads with
   NVRAM reads but keeping the multi-APDU control flow.
2. **Single synchronous SIGN_ALL APDU** that orchestrates the whole sequence
   on-device once nonce + msg are loaded.

**Decision.** Option 2.

**Rationale.**
- Simpler host code (5 APDUs vs 15+).
- Sign duration is ~1 sec on Nano S+ — well under any APDU timeout.
- Removes the need for L0 "double-feed" since NVRAM L0 is read directly when
  `do_after_right` actually needs it (vs streaming's redundant first L0
  reception that was immediately overwritten).
- Eliminates `cx_outsourced` accumulator state, MAC verification, decryption
  XOR — all unnecessary when the tree is in the same TCB as the seed.

**Trade-off.** Lose the granular per-step error reporting of the streaming
state machine. Mitigation: SIGN_ALL returns SWO_INCORRECT_DATA on any
internal failure; for debugging, fall back to streaming variant which still
ships in the same firmware.

---

## ADR-2b-2: BSS layout — separate fctx struct vs reuse streaming sctx

**Context.** Both streaming sign and flash sign alias their context onto
`_falcon_sign_area` (32 KB shared BSS). Streaming's `sctx` includes
`cx_outsourced_t outsourced`, `tag_buf[16]`, `accum_offset` for host-wire
accumulation, plus `_crypto_xof`. None of these are used by flash sign. Flash
sign on the other hand needs `z_pair_save[2*FN]` (8 KB) to preserve z0+z1
across s0/s1 (the streaming version has the host buffer them).

**Options considered.**
1. **Add `z_pair_save` to streaming sctx**, share the struct, set
   `outsourced/tag_buf/accum_offset` to zero in flash mode.
2. **Define a separate `falcon512_flash_sign_ctx_t`** with only the fields
   flash needs, aliased onto the same memory.

**Decision.** Option 2.

**Rationale.**
- Streaming sctx + z_pair_save would push BSS to ~32 KB, no headroom for
  future additions.
- Flash sctx has different fields anyway — sharing the struct just creates
  dead fields on each side.
- The aliasing is safe: streaming sign and flash sign are mutually exclusive
  per call (different INS), so the memory is never accessed concurrently
  through both type punnings.

**Trade-off.** Small code duplication for the shared fields (stk, ws, hm_sig,
sampler_context). Acceptable: the field names are identical, so the helpers
copied from streaming work after `sctx` → `fctx` rename without other edits.

---

## ADR-2b-3: NVRAM read pattern — direct memcpy vs read-then-verify

**Context.** Streaming sign uses `cx_outsourced_read_split(ctx, off, ct, len, tag)`
which performs HMAC-SHAKE verification + XOR decryption in place. The
authenticated blob model is needed because the encrypted tree lives on the
host filesystem (untrusted). For flash, the tree lives in device NVRAM
written by KEYGEN_EXPAND.

**Options considered.**
1. **Direct memcpy from NVRAM** — trust the NVRAM contents because they were
   written by code in the same firmware that holds the seed.
2. **Encrypt + MAC NVRAM contents** — write ciphertext + tag in
   KEYGEN_EXPAND, verify + decrypt in SIGN_ALL.

**Decision.** Option 1. Plaintext NVRAM, direct memcpy.

**Rationale.**
- TCB analysis: NVRAM contents are protected by the same secure element that
  protects the seed itself. An attacker who can corrupt NVRAM can already
  extract the seed; encrypting NVRAM with a key derived from that same seed
  adds no security.
- Simplifies the read loop to a single memcpy per node — much faster than
  SHAKE128-MAC verification (~50 µs per node × ~1024 nodes = 50 ms saved).
- KEYGEN_EXPAND becomes simpler (no encryption pass, no MAC computation).

**Trade-off.** If a hardware-glitching attacker can flip individual NVRAM
bytes during a sign, the corrupted byte will cause a bad sample → invalid
signature → norm check fails in `is_short_half`. So the device still rejects,
just at the final `do_compute_s1_and_check` step rather than at the per-node
MAC step. Fault-resistance is degraded vs streaming but not catastrophic.
Future hardening: optional "verify mode" that recomputes a SHAKE digest
of the NVRAM tree and compares against a digest stored at expand time.
