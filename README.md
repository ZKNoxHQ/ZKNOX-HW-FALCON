# ZKNOX-HW-FALCON

Falcon-512 and Falcon-1024 (Round 3) signatures on the Ledger Nano S+, built on Thomas Pornin's low-RAM
signing core ([c-fn-dsa-alt](https://github.com/pornin/c-fn-dsa-alt), September 2026) modified for Falcon
backward compatibility: the signatures verify with the Falcon Round 3 reference `verify_raw`, the PQClean
KAT-validated JS verifiers and the ZKNOX on-chain verifiers, unchanged.

One APDU signs. Key generation and signing run in a 27 648-byte working area, without expanded key, LDL tree,
NVM tree or host round trip. The private key is persisted per degree in the secure element's NVM, so a fresh
session signs directly. An SCA-protected Gaussian sampler (Lin et al., PKC 2025) is selectable at build time.

The previous implementation (v0.7.0, tree streamed by the host, INS 0x30..0x34) is archived under `legacy/`
with its own README.

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
src/falcon_core.h                     core selection (lowram | legacy)
tools/sim/                            host simulation of the handlers with a BOLOS shim
js/                                   device test and JS verifiers
legacy/                               v0.7.0 core, handlers, harness and README (archived)
```

RAM: `g_falcon_lr` = 29 848 B of BSS: the 27 648-byte working area shared by keygen and sign (keygen temp,
plus the encoded key emitted by the keygen, decoded to raw f, g, F, h before persistence), the output buffer
(header, nonce, raw s2), the message, the signing seed and the session seed. v0.7.0 needed 35 880 B of BSS plus
a 90 KB encrypted tree on the host.

## Key management

- Seed: SLIP-10 over the device mnemonic, path `m/44'/9004'/0'/0'/0'`, modifier `"Falcon-1024 seed"` or
  `"Falcon-512 seed"` (independent keys). Derived once per session into RAM, never written to NVM.
- NVM record per degree (`falcon_lowram_nvm.h`): `key_id | f | g | F | h | fmt | ready`, with
  `key_id = SHAKE256("falcon-key-id" ‖ seed)`. `ready` is cleared before a record is rewritten and set last.
- `FALCON_LR_KEYGEN` is idempotent: if the derived seed matches the stored `key_id`, it returns the stored
  public key in milliseconds and computes nothing. A new mnemonic invalidates the record and regenerates.
- `FALCON_LR_SIGN` needs neither KEYGEN nor any expansion in a fresh session. `fmt` invalidates records written
  by a firmware with another key layout.

## APDU specification

CLA `0xE0`. All INS take `P2 = logn`: `9` (Falcon-512) or `10` (Falcon-1024).

| INS | Name | P1 | Data | Response |
|-----|------|----|------|----------|
| `0x50` | `FALCON_LR_KEYGEN` | 0 | — | first 255 bytes of h (uint16 host order) |
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
make                          # FALCON_CORE=lowram, FALCON_SCA_PROTECT=1
make FALCON_SCA_PROTECT=0     # plain sampler
make FALCON_CORE=legacy       # archived v0.7.0 core from legacy/src (unmaintained)
```

The Nano S+ target is `cortex-m35p+nodsp -msoft-float`. Pornin's Cortex-M4 assembly uses DSP instructions and
FPU registers as scratch, so the C paths are compiled for now. Two of his assembly files are DSP-free
(`sign_sampler`, `codec`) and the Falcon reference's fpr assembly is plain Thumb-2: candidates for a later port.

## Performance

Host measurements (x86-64, pure C, same emulated arithmetic as the device) per signature:

| | Falcon-512 | Falcon-1024 |
|---|---:|---:|
| plain sampler | 2.5 ms, 56 K add + 48 K mul | 5.3 ms, 116 K add + 99 K mul |
| SCA-protected sampler | 15.9 ms, 252 K add + 306 K mul | 32.2 ms, 520 K add + 626 K mul |
| keygen (fixed point, no float) | 4.3 ms | 14.2 ms |

Upstream reports 13.45 Mcycles per Falcon-512 signature on a Cortex-M4 with assembly, about twice that in C;
the SCA countermeasure multiplies the signature cost by about 6 (measured on host). Device timings are printed
per APDU by `js/falcon-lowram-test.js` and will replace these numbers once measured (v0.7.0: 12.8 s per
Falcon-1024 signature, 17.4 s protected, at 32 MHz).

## Testing

- `tools/sim`: `./build.sh [SCA=0|1] && python3 derive_seed.py && ./sim_lowram [N]` drives the unmodified
  handlers through `apdu_dispatcher()` with a BOLOS shim (yellow×12 seeds derived on host). It checks the
  public keys against a host run of the keygen, verifies every signature with the archived Falcon reference
  `verify_raw`, replays a signature after a simulated restart without KEYGEN (byte-identical with the same
  seed), checks that a repeated KEYGEN writes nothing to NVM, and reports ‖s‖² statistics against 2n·σ².
- `js/falcon-lowram-test.js [logn] [count] [--seeded]`: device flow with per-APDU timings and JS verification.
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
  Falcon") and attacks on the FFT are out of scope, as in v0.7.0.
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
