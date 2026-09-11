# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2023-10-06

### Changed

- Improving the settings use case in order to be able to use app settings parameters stored in NVM
- add a NBGL use case choice when a setting switch is toggled

## [2.0.0] - 2023-07-10

### Added

- Stax porting
- Extensive CI, including mandatory `guidelines_enforcer.yml`
- Extensive `README.md` to modify/compile/test the application on most OS (Linux, MacOS, Windows)
- Extensive `Ragger` tests

### Changed

- Simplified `Makefile` (complexity delegated to the SDK's `Makefile.standard_app`)
- Simplified overall code (moved into the SDK)
- Improving several UI flows to fit Ledger UI guidelines
- Removing `TRY`/`CATCH` usage (using `_no_throw` SDK functions)
- Cleaning unnecessary resources (moved into the SDK)

### Fixed

- Multiple minor lint, prototype or misspell fixes

## [1.0.1] - 2021-01-11

### Fix

- Missing header includes

## [1.0.0] - 2020-11-19

### Added

- Initial commit with the brand new Boilerplate application

## [Unreleased] — Falcon on the low-RAM core (c-fn-dsa-alt in Falcon mode)

### Added
- `src/falcon_lowram/`: Thomas Pornin's c-fn-dsa-alt (public domain, commit 77e4870) in Falcon Round 3 mode
  (`FNDSA_FALCON_R3=1`: big-endian `hash_to_point` over nonce || msg, raw f|g|F key input, raw s2 output),
  with the Lin et al. (PKC 2025) SCA-protected SamplerZ ported onto it (`FNDSA_SAMPLER_PROTECT`).
  Files renamed with the `fndsa_` prefix (the SDK flattens object names); `fndsa_sysrng.c` uses `cx_rng_no_throw`.
- `src/handler/handler_falcon_lowram.c`: INS 0x50 KEYGEN, 0x51 GET_PK, 0x53 SIGN (INIT / FEED_MSG / FEED_SEED / GEN_SEED /
  SIGN_ALL / GET_NONCE), 0x54 GET_SIG, all with P2 = logn (9 or 10). Single-APDU signature, no tree, no expand,
  no host round trip. Key persisted per degree in NVM (`falcon_lowram_nvm.h`: key_id | f | g | F | h), bound to
  `key_id = SHAKE256("falcon-key-id" || seed)`; KEYGEN idempotent; SIGN needs no KEYGEN in a fresh session.
- `src/falcon_core.h` + Makefile `FALCON_CORE=lowram|legacy`: the two cores are exclusive (same RAM budget).
  Default `lowram`; `legacy` rebuilds the v0.7.0 tree-streaming app (INS 0x30..0x34) unchanged.
- Falcon-512 seed derivation (`falcon512_derive_seed`, modifier "Falcon-512 seed", same path).
- `tools/sim/`: host simulation of the new APDUs with the unmodified app sources (BOLOS shim), oracle on the
  legacy reference `verify_raw`. `js/falcon-lowram-test.js`: device test (keygen, sign, verify, timings).
  `js/falcon512-verify.js` added, `js/falcon1024-verify.js` bound updated to Round 3 (70265242).

### Moved
- The v0.7.0 core (reference library `zknox/falcon`, `handler_falcon*`, `cx_outsourced`, `falcon_inner.h`,
  `zkn_*.h`, the streaming JS harness and its yellow×12 vectors) and the previous README are archived under
  `legacy/`; `make FALCON_CORE=legacy` builds them from `legacy/src`. `tools/apply_lowram_layout.sh` removes
  the old copies from `src/` and `js/` after unzipping a delivery.

### RAM
- `g_falcon_lr` = 29 848 B of BSS (27 648 B working area shared by keygen and sign + output buffers), instead of
  `g_zknox` = 35 880 B + the NVM tree. Stack: ~2.6 KB at the deepest point of the sign (C recursion, x86-64 upper bound).

### Compatibility
- Signatures are standard Falcon Round 3 (verified by the legacy reference `verify_raw` and the JS verifiers);
  the sampler is Round 3 with a 79-bit base sampler; ||s||² statistics match 2n·σ².
- Keys change: the fixed-point keygen expands the seed differently from the reference. yellow×12 public keys:
  Falcon-512 h sha256 `d058c32a…`, Falcon-1024 h sha256 `6a3c1570…` (deterministic, checked by tools/sim).
- Cortex-M4 assembly of c-fn-dsa-alt is not built (`FNDSA_ASM_CORTEXM4=0`): it needs DSP and FPU registers,
  absent from the Nano S+ target (`cortex-m35p+nodsp -msoft-float`). C paths only, for now.
