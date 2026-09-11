# Architecture Decision Records

## ADR-0003 — Replace the tree-streaming core by Pornin's low-RAM core (c-fn-dsa-alt) in Falcon mode

**Status**: accepted (device validation pending).

**Context**: the v0.7.0 core needs an expanded key (LDL tree, 90 KB for 1024) that the Nano S+ cannot hold, hence
the encrypted tree streamed by the host and z0/z1 round trips (12.8 s per Falcon-1024 signature, 17.4 s with the
SCA-protected sampler, ~730 APDUs). Thomas Pornin's c-fn-dsa-alt (September 2026) signs without a tree in
20n+31 bytes (10 271 / 20 511 B) and generates keys in fixed point in 22n+31 bytes; its lattice math and
parameters are exactly Falcon Round 3, only the FN-DSA encodings and hashing differ.

**Decision**: use c-fn-dsa-alt as the signing core, in a Falcon Round 3 compatibility mode confined to the
periphery (`hash_to_point` endianness and input, raw key input, raw s2 output), so that the existing verifiers
(PQClean KATs, JS, on-chain) are untouched. Port the Lin et al. SamplerZ countermeasure onto its sampler.
The legacy core stays selectable on `main` (`FALCON_CORE=legacy`) for history; the `lowram-light` branch
drops it.

**Consequences**:
- One APDU signs; keygen + sign fit in a 27 648-byte area; no NVM tree, no host round trip, no z export.
- New keys for existing mnemonics (different seed expansion); the encoded private key is what is persisted,
  the seed only derives `key_id`.
- The c-fn-dsa-alt Cortex-M4 assembly is unusable as-is on the M35P (DSP instructions, FPU scratch registers):
  start in C, then port `sign_fpr` (base Thumb-2) and, if measurements justify it, the NTT and Keccak routines.
- SCA-protected sampler: same countermeasure, ~×6 on the signature (measured on host), 1 216 B of BSS workspace.
