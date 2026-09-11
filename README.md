# ZKNOX-HW-FALCON

Falcon-512 and Falcon-1024 (Round 3) signatures on the Ledger Nano S+, built on Thomas Pornin's low-RAM
signing core ([c-fn-dsa-alt](https://github.com/pornin/c-fn-dsa-alt), September 2026) modified for Falcon
backward compatibility: the signatures verify with the Falcon Round 3 reference `verify_raw`, the PQClean
KAT-validated JS verifiers and the ZKNOX on-chain verifiers, unchanged.

One APDU signs. Key generation and signing run in a 27 648-byte working area, without expanded key, LDL tree,
NVM tree or host round trip. Nothing is stored: the key is regenerated from the SLIP-10 seed by the first APDU
of a session that needs it (fixed-point keygen, deterministic) and kept in RAM, in the Ledger way; persisting it
in NVM is a build option. An SCA-protected Gaussian sampler (Lin et al., PKC 2025) is selectable at build time.

## Branches

| Branch | Content |
|---|---|
| `lowram-light` | This branch: the low-RAM core only. No legacy code, no core switch; `make` builds the app described here. |
| `main` | Same low-RAM app plus the archived v0.7.0 implementation under `legacy/` (tree streamed by the host, INS 0x30..0x34, its README and JS harness), selectable with `make FALCON_CORE=legacy`. Kept for history and for re-running the old benchmarks. |
| `feat/512` | Historical Falcon-512 work on the streaming core, superseded by this branch (both degrees are handled by the same handler here). |

## Benchmark

Measured on a Ledger Nano S+ (32 MHz), C paths only, wall clock per APDU from `js/falcon-lowram-test.js`
(USB round trip included, negligible against the computation):

| | Falcon-512 | Falcon-1024 | v0.7.0, Falcon-1024 (`main`, `legacy/`) |
|---|---:|---:|---:|
| Key generation (once per session and per degree) | 1.05 s | 3.2 s | 17.8 s, plus 14.6 s of expand |
| Signature, plain sampler | 0.63 s | 1.35 s | 12.8 s |
| Signature, SCA-protected sampler | 3.2 s | 6.35 s | 17.4 s |
| First signature of a session (plain / protected) | 1.7 s / 4.3 s | 4.5 s / 9.5 s | ≈ 45 s / 50 s |
| s2 transfer (GET_SIG) | 45 ms | 75 ms | — |
| APDUs per signature | 13 | 13 | ≈ 730 |
| Secret material at rest | none | none | encrypted tree on the host |
| BSS | 29 848 B | 29 848 B | 35 880 B |

Signatures are bit-identical to the host implementation for the same seed, message and key, in both sampler
builds; the SCA countermeasure costs ×5 on the signature, entirely in the sampler.

## What the core is

c-fn-dsa-alt is an alternate implementation of FN-DSA (the upcoming NIST standardization of Falcon) whose
signing procedure avoids the expanded key entirely: a new FFT variant computes the Gram matrix and the LDL
tree on the fly, the sampling recursion works in 20n+31 bytes, and the key generation is fixed-point
(no floating-point emulation at all). Its lattice arithmetic and its parameters (σ, σ_min, β²) are exactly
those of Falcon Round 3; only the FN-DSA encodings and the message hashing differ from Falcon.

| | Falcon-512 | Falcon-1024 |
|---|---:|---:|
| sign, temporary area (20n+31) | 10 271 B | 20 511 B |
| keygen, temporary area (22n+31) | 11 295 B | 22 559 B |
| sign, stack (C recursion, upper bound measured on x86-64) | 2 344 B | 2 456 B |
| keygen, stack | 1 144 B | 1 144 B |
| emulated-float ops per signature (add / mul) | 56 K / 48 K | 116 K / 99 K |
| same, v0.7.0 core | 130 K / 101 K | 289 K / 221 K |

## Modifications to Pornin's code (`src/falcon_lowram/`)

Upstream: c-fn-dsa-alt commit `77e4870` (public domain). Files keep their upstream names with an `fndsa_`
prefix and the internal `fndsa_` symbol prefix, so that upstream diffs stay trivial to track. The changes
are a compile-time option, `FNDSA_FALCON_R3=1`, plus the sampler countermeasure:

1. **`hash_to_point`** (`fndsa_util.c`): SHAKE256(nonce ‖ message) with the message of arbitrary length,
   16-bit words read big-endian, as in the Falcon reference. FN-DSA reads them little-endian and hashes
   nonce ‖ mu with mu = SHAKE256(H(pk) ‖ ctx ‖ id ‖ message) (BUFF); none of that is compiled in.
2. **Private key input** (`fndsa_sign_core.c`, `KEY_DECODE`): f, g, F are given raw (int8, contiguous),
   i.e. a Falcon key, instead of the FN-DSA packed encoding.
3. **Signature output** (`fndsa_sign_core.c`): the raw s2 polynomial (int16) follows the header byte and the
   40-byte nonce; the FN-DSA compressed codec (LSB-first, unlike Falcon's) is bypassed. The L2 norm check is
   the Round 3 one; the FN-DSA infinity-norm check is kept, which only makes the output a subset of valid
   Falcon signatures.
4. **Entry point** (`fndsa_sign.c`): `fndsa_falcon_sign_seeded_temp(logn, fgF, msg, msg_len, seed, seed_len,
   out, out_len, tmp, tmp_len)`, hedged like upstream (SHAKE256 over a domain string, H(f ‖ g), the message
   and the caller's 40-byte seed) but with its own domain string.
5. **SCA-protected SamplerZ** (`fndsa_sign_sampler.c`, `FNDSA_SAMPLER_PROTECT=1`): Algorithms 5, 6, 7 of
   Lin et al. (PKC 2025), ported from the v0.7.0 implementation onto this core's primitives (79-bit base
   sampler table, SHAKE256 sampling PRNG, `expm_p63`): comparisons encoded {1,2}, four half-Gaussian draws
   with random selection, sign in {1,2}, x and BerExp computed for all 2 × 19 candidates then selected in
   constant time. Statistically indistinguishable from the plain sampler (χ² on 300 000 draws per (μ, σ)).
6. **Platform**: `fndsa_sysrng.c` on `cx_rng_no_throw` (only reached by non-seeded APIs, which the app does
   not use); the Cortex-M4 assembly is not built (`FNDSA_ASM_CORTEXM4=0`), see Performance.

The key generation is untouched: the fixed-point NTRU solver produces Falcon keys (f, g, F with the Falcon
coefficient bounds, G recoverable, GS norm bound 0.999·1.17√q, stricter than Falcon's). Its seed expansion is
Pornin's, not the Falcon reference's, so a given mnemonic yields a different key than under v0.7.0.

With `FNDSA_FALCON_R3=0` the same sources are the unmodified FN-DSA implementation; upstream's test suite
still passes on them (14/14). FN-DSA proper lives in a separate ZKNOX repository.

## Architecture

```
src/falcon_lowram/                    Pornin's core in Falcon mode (see its README)
src/handler/handler_falcon_lowram.c   APDUs 0x50..0x54, session seed, NVM persistence
src/handler/falcon_lowram_nvm.h       NVM key records
src/zknox/keys/derive.c               SLIP-10 seed derivation (Falcon-1024 and Falcon-512 modifiers)
tools/sim/                            host simulation of the handlers with a BOLOS shim
js/                                   device test and JS verifiers
```

RAM: `g_falcon_lr` = 29 848 B of BSS: the 27 648-byte working area shared by keygen and sign (keygen temp,
the encoded key emitted by the keygen, then the raw session key f, g, F, h kept after the signing temp), the output buffer
(header, nonce, raw s2), the message, the signing seed and the session seed. v0.7.0 needed 35 880 B of BSS plus
a 90 KB encrypted tree on the host.

## Key management

- Seed: SLIP-10 over the device mnemonic, path `m/44'/9004'/0'/0'/0'`, modifier `"Falcon-1024 seed"` or
  `"Falcon-512 seed"` (independent keys). Derived into RAM only when a keygen runs, wiped right after.
- Default (`FALCON_LR_PERSIST_KEY=0`): no key at rest. The first APDU of a session that needs the key
  (KEYGEN, GET_PK or SIGN_ALL) regenerates it from the seed and keeps f, g, F, h in the tail of the working
  area for the rest of the session; the other degree replaces it. The keygen being deterministic, the key is
  the same every time. Cost: one keygen per session and per degree (1.05 s for 512, 3.2 s for 1024).
- Option (`FALCON_LR_PERSIST_KEY=1`): NVM record per degree (`falcon_lowram_nvm.h`):
  `key_id | f | g | F | h | fmt | ready`, `key_id = SHAKE256("falcon-key-id" ‖ seed)`, `ready` cleared before a
  rewrite and set last. A session then signs without any keygen; a new mnemonic regenerates. Useful only if the
  keygen turns out too slow for the UX.
- `FALCON_LR_KEYGEN` P1=0 is idempotent within a session (and across sessions with NVM); P1=1 forces a
  recomputation (benchmark).

## APDU specification

CLA `0xE0`. All INS take `P2 = logn`: `9` (Falcon-512) or `10` (Falcon-1024).

| INS | Name | P1 | Data | Response |
|-----|------|----|------|----------|
| `0x50` | `FALCON_LR_KEYGEN` | 0 (1: force recomputation) | — | first 255 bytes of h (uint16 host order) |
| `0x51` | `FALCON_LR_GET_PK` | chunk index | — | 255-byte chunks of h, 2n bytes in total |
| `0x53` | `FALCON_LR_SIGN` | `0x00` INIT | — | — |
| | | `0x06` FEED_MSG | 32 bytes (hash of the payload) | — |
| | | `0x08` FEED_SEED | 40 bytes | deterministic signature (test, KAT) |
| | | `0x09` GEN_SEED | — | 40-byte seed from the TRNG |
| | | `0x10` SIGN_ALL | — | signs; one signature per seed |
| | | `0x91` GET_NONCE | — | 40-byte nonce |
| `0x54` | `FALCON_LR_GET_SIG` | chunk index | — | 255-byte chunks of s2 (int16 host order), 2n bytes |

Verification (Falcon Round 3): `c = hash_to_point(SHAKE256(nonce ‖ msg))`, `s1 = c − s2·h mod q`,
`‖(s1, s2)‖² ≤ 34034726` (512) or `70265242` (1024). The host applies the Falcon compressed encoding to s2 if it
needs the standard signature format.

Status words: `0x9000` success, `0x6A86` bad P1/P2 (including an unsupported logn), `0x6A87` bad length,
`0x6A80` state error (no key for this seed, message or seed missing, signature not available).

## Build options

```
make                            # FALCON_SCA_PROTECT=1, FALCON_LR_PERSIST_KEY=0
make FALCON_SCA_PROTECT=0       # plain sampler
make FALCON_LR_PERSIST_KEY=1    # key persisted in NVM (no keygen per session)
```

The Nano S+ target is `cortex-m35p+nodsp -msoft-float`. Pornin's Cortex-M4 assembly uses DSP instructions and
FPU registers as scratch, so the C paths are compiled for now. Two of his assembly files are DSP-free
(`sign_sampler`, `codec`) and the Falcon reference's fpr assembly is plain Thumb-2: candidates for a later port.

## Performance notes

Device numbers are in the Benchmark section. The keygen is the fixed-point NTRU solver (no floating-point
emulation); with the key kept in RAM it runs once per session. Host reference (x86-64, same C code):
2.5 / 5.3 ms per plain signature, 15.9 / 32.2 ms protected, 4.3 / 14.2 ms keygen, 56 K add + 48 K mul (512)
and 116 K add + 99 K mul (1024) emulated-float operations per plain signature (the v0.7.0 core needed
130 K + 101 K and 289 K + 221 K for the signature alone). Next levers, in order: the fpr routines in Thumb-2
assembly (the Falcon reference's, DSP-free), Pornin's DSP-free assembly of the sampling recursion (stack from
~2.5 KB to ~1 KB), then the NTT and Keccak routines.

## Testing

- `tools/sim`: `[SCA=0|1] [PERSIST=0|1] ./build.sh && python3 derive_seed.py && ./sim_lowram [N]` drives the unmodified
  handlers through `apdu_dispatcher()` with a BOLOS shim (yellow×12 seeds derived on host). It checks the
  public keys against a host run of the keygen, verifies every signature with a Falcon Round 3 oracle built on
  the core's own primitives, replays a signature after a simulated restart without KEYGEN (byte-identical with the same
  seed), checks that a repeated KEYGEN writes nothing to NVM, and reports ‖s‖² statistics against 2n·σ².
- `js/hw-app-falcon`: `@zknox/hw-app-falcon`, the Ledger hw-app for this signer (`getPublicKey`, `signHash`,
  `generateKey`), transport-agnostic. `npm test` runs on a mock transport; `npm run test:device` runs on the
  device (identity, both degrees, keygen timing, TRNG signatures verified on the host, seeded yellow x12 KATs
  that also identify the sampler build). Verifier-specific encodings are out of its scope: they belong to the
  verifier (ETHFALCON) and account packages.
- `js/falcon-lowram-test.js [logn] [count] [--seeded] [--force-keygen]`: device flow on top of the hw-app with
  per-APDU timings and JS verification; `--force-keygen` measures the actual key generation.
- `js/kat_validation`: the JS verifier against the PQClean Falcon-1024 KATs.

Test vectors, mnemonic `yellow × 12`, no passphrase (SHA-256 of the raw h):

| Key | SHA-256 |
|-----|---------|
| Falcon-512 h | `d058c32a17758dee5cccd3e77a58591be757dda43af812c6f5043d23d841e0bc` |
| Falcon-1024 h | `6a3c1570bd7b86c2ace25d449a893d077e0870f485182972df3c0e8df3b44f6f` |

Signatures are randomized (TRNG seed) unless FEED_SEED is used.

## Security notes

- The SCA-hardened build targets the half-Gaussian and sign leakages of the integer Gaussian sampler
  (Guerreau et al. 2022; Zhang, Lin, Yu, Wang 2023): with the Lin et al. countermeasure the single-trace
  template accuracy drops to about 58–62 %, below the 65 % threshold above which their key recovery needs
  more than 10 million traces. Fault attacks, floating-point error sensitivity ("Do Not Disturb a Sleeping
  Falcon") and attacks on the FFT are out of scope.
- The core is constant-time by construction (upstream); the countermeasure adds no branch on secrets.
- The private key sits at rest in the secure element's NVM; the seed only derives `key_id`.

## References

- T. Pornin, *A RAM-Efficient Implementation of Falcon* (paper in the c-fn-dsa-alt repository, `tex/fndsa-small-ram.pdf`), https://github.com/pornin/c-fn-dsa-alt (2026).
- Falcon Round 3 specification, https://falcon-sign.info.
- X. Lin et al., *Thorough Power Analysis on Falcon Gaussian Samplers and Practical Countermeasure*, PKC 2025.
- S. Zhang, X. Lin, Y. Yu, W. Wang, *Improved Power Analysis Attacks on Falcon*, EUROCRYPT 2023.
- M. Guerreau, A. Martinelli, T. Ricosset, M. Rossi, *The Hidden Parallelepiped Is Back Again*, TCHES 2022.

## License

App: see `LICENSE.md`. `src/falcon_lowram/` derives from c-fn-dsa-alt, released by its author into the public
domain.
