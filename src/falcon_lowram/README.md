# falcon_lowram — Falcon Round 3 on Thomas Pornin's low-RAM signing core

Source: https://github.com/pornin/c-fn-dsa-alt (commit 77e4870, public domain). The files keep their
upstream names with an `fndsa_` prefix so that upstream diffs stay easy to track; the internal symbols
keep Pornin's `fndsa_` prefix for the same reason.

What is compiled here is NOT FN-DSA: the option `FNDSA_FALCON_R3=1` (see `fndsa_inner.h`) turns the core
into a Falcon Round 3 signer:
- `hash_to_point`: SHAKE256(nonce || message), 16-bit words read big-endian, exactly as the Falcon reference
  (no BUFF / mu, no context string, no pre-hash identifier);
- private key given raw (f | g | F, int8), i.e. a Falcon key; the fixed-point keygen produces Falcon keys;
- output is the raw s2 polynomial; the app sends it as-is (no FN-DSA little-endian codec, no NTT-form key).
The lattice math and the parameters (sigma, sigma_min, l2 bound) are those of Falcon Round 3 in both modes.

`FNDSA_SAMPLER_PROTECT=1` selects the SCA-protected SamplerZ (Lin et al., PKC 2025) ported on this core.

RAM: signing 20n+31 bytes of temp (10 271 / 20 511), keygen 22n+31 (11 295 / 22 559), no LDL tree.
Entry points used by the app: `fndsa_keygen_seeded_temp()` and `fndsa_falcon_sign_seeded_temp()`.
