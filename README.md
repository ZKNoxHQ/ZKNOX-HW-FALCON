# ZKNOX-HW-FALCON

Falcon-1024 post-quantum signature scheme for Ledger Nano S+, with optional side-channel hardening.

This is a hardware wallet implementation of [Falcon](https://falcon-sign.info/) (NIST PQC standard, FN-DSA / FIPS 206) running on the Ledger Nano S+ (STM32L4-class, Cortex-M33 @ 32MHz, 40 KB SRAM). The challenge: Falcon-1024 signing requires a 122 KB LDL tree which does not fit in device RAM. The solution: stream the encrypted and authenticated tree from the host on demand.

## Architecture

The LDL tree (1023 internal nodes + 1024 leaves, total 122,864 B) is computed once during `KEYGEN_EXPAND` and stored on the host in encrypted form. During `SIGN`, the device walks the tree depth-first, requesting one node at a time from the host.

```
                  ┌──────────────┐                   ┌──────────────┐
                  │     HOST     │                   │  NANO S+     │
                  │              │                   │  (40KB SRAM) │
                  │  encrypted   │  ──── APDU ────▶  │              │
                  │  LDL tree    │  ◀─── APDU ────   │   sampler    │
                  │  (122 KB)    │                   │              │
                  └──────────────┘                   └──────────────┘
```

Each tree record is XOR-encrypted with a SHAKE256 keystream and authenticated with a SHAKE256 MAC. The keys are derived once per `KEYGEN_EXPAND` from a BIP-32 derivation. Hosts cannot forge nodes (MAC) and cannot read tree contents (encryption).

### Tree streaming construction

```
record       = ciphertext || tag                              (16 + len B)
ciphertext   = plaintext XOR SHAKE256(tree_key || offset)     (per-node keystream)
tag          = SHAKE256(mac_key || offset || ciphertext)[:16] (per-node MAC)
```

Where `tree_key` and `mac_key` are derived as `SHAKE256(seed || "falcon-tree-key")` and `SHAKE256(seed || "falcon-tree-mac")` respectively, with the seed itself derived via BIP-32 from `m/44'/9004'/0'/0/0`.

## APDU specification

Class byte: `CLA = 0xE0` (standard).

| INS  | Name            | Description                                         |
|-----:|-----------------|-----------------------------------------------------|
| 0x30 | `KEYGEN`        | Generate Falcon-1024 keypair on device              |
| 0x31 | `GET_PK`        | Read the 2048 B public key                          |
| 0x33 | `SIGN`          | Sign a message (multi-step, streamed tree)          |
| 0x34 | `KEYGEN_EXPAND` | Compute LDL tree, return encrypted blob to host     |

### `INS_FALCON_KEYGEN` (0x30)

Single-shot. Derives a Falcon-1024 keypair from `m/44'/9004'/0'/0/0`. Stores the secret in BSS for subsequent `GET_PK`, `SIGN`, `KEYGEN_EXPAND` calls.

| Field | Value |
|-------|-------|
| P1    | `0x00` |
| P2    | `0x00` |
| Lc    | `0x00` |
| Le    | `0x00` |
| Resp  | `0x9000` on success |

### `INS_FALCON_GET_PK` (0x31)

Returns the 2048 B public key (Falcon-1024 raw format, 14 bits per coefficient × 1024 packed into 1792 B + header).

| Field | Value |
|-------|-------|
| P1    | `0x00` |
| P2    | `0x00` |
| Lc    | `0x00` |
| Le    | up to 255 (chunked, see device chunking) |
| Resp  | public key bytes \|\| `0x9000` |

### `INS_FALCON_KEYGEN_EXPAND` (0x34)

Streams the encrypted LDL tree to the host. Six P1 sub-commands:

| P1   | Sub-command       | Direction       | Description                          |
|-----:|-------------------|-----------------|--------------------------------------|
| 0x00 | `COMPUTE_L0`      | none            | Compute the L0 root node             |
| 0x01 | `GET_L0`          | device → host   | Return the L0 record (8208 B)        |
| 0x02 | `PREP_RIGHT`      | none            | Initialize right subtree DFS         |
| 0x03 | `GET_NEXT_R`      | device → host   | Return next right-child record       |
| 0x04 | `PREP_LEFT`       | none            | Initialize left subtree DFS          |
| 0x05 | `GET_NEXT_L`      | device → host   | Return next left-child record        |

Total wire size: 122,864 B in approx. 2,242 APDUs.

### `INS_FALCON_SIGN` (0x33)

Streamed signature. Eleven P1 sub-commands:

| P1   | Sub-command         | Direction       | Description                              |
|-----:|---------------------|-----------------|------------------------------------------|
| 0x06 | `FEED_NONCE_HOST`   | host → device   | Provide host-generated 40 B nonce        |
| 0x07 | `FEED_NONCE_DEVICE` | none            | Generate nonce on device (preferred)     |
| 0x08 | `FEED_MSG`          | host → device   | Stream the message to hash               |
| 0x09 | `COMPUTE_HM`        | none            | Compute hash-to-point (`hm`)             |
| 0x91 | `GET_NONCE`         | device → host   | Read back the device-generated nonce     |
| 0x02 | `COMPUTE_TARGET`    | none            | Init sampler ctx, compute target vector  |
| 0x03 | `FEED_TREE_STREAM`  | host → device   | Stream encrypted tree node, decrypt+MAC  |
| 0x04 | `FEED_SWAP`         | host → device   | Stream L0 record + parent t1 + z0/z1     |
| 0x05 | `GET_SWAP`          | device → host   | Return computed z0/z1 for re-injection   |
| 0xA0 | `GET_SIG`           | device → host   | Return the 2048 B signature (chunked)    |

The `hash_to_point` is computed entirely on the device — the host never sees the unhashed message-to-be-signed in plaintext, only what it provided as input.

### Status words

| SW       | Meaning                                |
|---------:|----------------------------------------|
| `0x9000` | Success                                |
| `0x6E00` | Wrong CLA                              |
| `0x6D00` | Unknown INS                            |
| `0x6B00` | Wrong P1/P2                            |
| `0x6A80` | Wrong data (e.g. MAC mismatch)         |
| `0x6985` | Conditions of use not satisfied        |
| `0x6F00` | Internal error                         |

## Build options

### Standard build (no SCA hardening)

```bash
make clean && make load
```

This builds the Falcon-1024 reference sampler from the Falcon team without modification.

### SCA-hardened build

Edit `Makefile`, add to the `DEFINES` section:

```makefile
DEFINES += FALCON_SCA_PROTECT=1
```

Note: the Ledger SDK adds `-D` automatically — do NOT write `DEFINES += -DFALCON_SCA_PROTECT=1`.

Then:

```bash
make clean && make load
```

This activates the side-channel countermeasures from:

> Lin, Zhang, Yu, Wang, You, Xu, Wang. _Thorough Power Analysis on Falcon Gaussian Samplers and Practical Countermeasure._ PKC 2025.
> [eprint.iacr.org/2025/351](https://eprint.iacr.org/2025/351) · [code](https://github.com/lxhcrypto/FalconAnalysis)

The protection covers two power-analysis leakage sources identified in the academic literature:

| Leakage | Attack | First demonstrated by |
|---------|--------|------------------------|
| Half-Gaussian leakage (z+ = 0 vs z+ ≠ 0) | Single-trace key recovery | [Karabulut & Aysu, DAC 2021](https://eprint.iacr.org/2021/772) |
| Sign leakage (b = 0 vs b = 1)            | Single-trace key recovery | [Zhang, Lin, Yu, Wang, EUROCRYPT 2023](https://eprint.iacr.org/2023/224) |
| Hidden parallelepiped (preimage)         | Power analysis            | [Guerreau et al., TCHES 2022](https://eprint.iacr.org/2022/057) |

Three countermeasures from Lin et al. (Algorithms 5, 6, 7) are activated together:

- **BaseSampler (Alg. 5)** — encode the last subtraction of `[u < RCDT[i]]` as `{1, 2}` instead of `{0, 0xFF}` (eliminates 8-bit Hamming weight gap).
- **SamplerZ (Alg. 6)** — call BaseSampler 4 times per iteration, randomly select one; precompute z and x values for both possible signs `b' ∈ {1, 2}` and all 19 possible `z+` values.
- **BerExp (Alg. 7)** — compute all 19 × 2 = 38 `(b', z+)` decompositions, index at the very end.

The protected build is **wire-compatible** with the unprotected build (same APDU spec, same key size, same signature size). The pk and tree wire formats are byte-identical because keygen does not use the protected sampler. Signatures produced by the two builds are different (different PRNG tape) but both verify under the same public key.

## Benchmarks

### Latencies (Ledger Nano S+ @ 32 MHz, USB HID transport)

| Phase            | Unprotected | SCA-hardened | Ratio  |
|------------------|------------:|-------------:|-------:|
| `KEYGEN`         | 17.8 s      | 17.8 s       | 1.00 × |
| `KEYGEN_EXPAND`  | 14.6 s      | 14.6 s       | 1.00 × |
| `SIGN`           | 12.8 s      | 17.4 s       | 1.36 × |

The SCA hardening only affects the sign path. Key generation and tree expansion are byte-for-byte identical between the two builds — they do not invoke the protected sampler.

### Sign breakdown (unprotected vs SCA-hardened)

| Stage                    | Unprotected | SCA-hardened | Notes                          |
|--------------------------|------------:|-------------:|--------------------------------|
| `hm` (hash-to-point)     | 13 ms       | 13 ms        | unchanged                      |
| `target` (sampler init)  | 257 ms      | 257 ms       | unchanged                      |
| right subtree DFS        | 4255 ms     | 6583 ms      | `+2.3 s` (sampler 4× cost)     |
| left subtree DFS         | 4252 ms     | 6567 ms      | `+2.3 s`                       |
| transport + misc         | ~4.0 s      | ~4.0 s       | unchanged                      |

The streaming layer (encrypted-RAM MAC verification + decryption) accounts for roughly 75% of the sign time and is unaffected by the SCA hardening, which is why the overall overhead (×1.36) is much smaller than the ×3.3 reported by Lin et al. on Intel — the streaming amortizes the per-node cost.

### Communication

- Total APDUs per sign: ~729 (1.5 s at 2 ms USB HID round-trip)
- Wire size out (sig): 2048 B
- Wire size in (tree+message): 122,864 + ~50 B
- Maximum APDU payload: 255 B (standard length)

### Test vectors (mnemonic `yellow × 12`)

| Field | SHA-256 |
|-------|---------|
| `pk`  | `abda0932325ead2b390ba6542d6ff45b02e03b2ffdafd338f39667dc152a40d3` |
| `wire` (encrypted tree, unprotected & protected) | `855edeedfacc2b4b56f6b5f5b688bf8b5fed4d7f02984633aeb88fdd48efe3d4` |

Sign output is non-deterministic (depends on device PRNG), so `sig` SHA-256 differs across runs and across builds. End-to-end verification is checked by the JavaScript host harness via `verify_raw`.

### Security claims

The SCA-hardened build reduces single-trace template-attack accuracy on the integer Gaussian sampler from ~98% to ~58% (Lin et al., Table 5), pushing the number of traces required for full key recovery from approximately 6,500 to **above 10 million**, which is considered impractical for most attack scenarios.

This work covers power and electromagnetic side-channel attacks on the integer sampler. It does **not** cover:

- Fault injection on the integrity layer (open problem)
- Cache attacks (not applicable on Cortex-M33 without cache)
- Access pattern leakage in the streaming layer (orthogonal protection)
- Pre-image computation leakage in `t = c · B^{-1}` (see Karabulut & Aysu DAC 2021; partially addressed by [Chen & Chen TCHES 2024](https://tches.iacr.org/index.php/TCHES/article/view/11286) for the FP multiplication, not integrated here)

## Repository layout

```
.
├── Makefile                          Build rules (Ledger SDK)
├── ledger_app.toml                   App metadata
├── docker.sh / load.sh               Build & flash helpers
├── doc/                              APDU spec details
├── glyphs/, icons/                   UI assets
├── src/
│   ├── main.c, app_main.c            Entry points
│   ├── globals.h                     BSS budgets, derivation paths
│   ├── apdu/                         Dispatcher
│   ├── handler/
│   │   ├── handler_falcon_keygen.c
│   │   ├── handler_falcon_get_pk.c
│   │   ├── handler_falcon_keygen_expand.c
│   │   ├── handler_falcon_sign.c
│   │   ├── cx_outsourced.{c,h}      Encrypted RAM module
│   │   └── ...
│   ├── ui/                           Display flows
│   ├── zknox/
│   │   ├── falcon/                   Falcon reference (vendored)
│   │   │   ├── sign.c                Includes SCA-hardened sampler
│   │   │   ├── keygen.c, fft.c, fpr.c, codec.c, vrfy.c, ...
│   │   │   └── inner.h
│   │   ├── keys/derive.c             BIP-32 derivation
│   │   └── zkn_*.h                   Common headers
│   └── falcon_inner.h                Project-wide internal header
└── js/
    ├── falcon1024-full-chain.js      End-to-end test
    ├── falcon1024-ledger-sign.js     Sign-only host
    ├── falcon1024-ledger-keygen-expand.js
    ├── falcon1024-verify.js          Standalone verifier
    ├── falcon1024-kat-verify.js      KAT validation
    └── kat_validation/               PQClean Falcon-1024 KATs
```

## Running the test harness

```bash
cd js
npm install
node falcon1024-full-chain.js
```

Expected output starts with `═══ Falcon-1024 v0.7.0 full-chain test ═══` and ends with `═══ ✅ FULL CHAIN PASSED ═══` after KEYGEN, KEYGEN_EXPAND, SIGN, and verify steps complete.

The full chain runs `KEYGEN` → `KEYGEN_EXPAND` → `SIGN` → `verify_raw` and validates that all four are mutually consistent. The pk and wire SHA-256 are also compared against the published reference (mnemonic `yellow × 12`).

## License

Apache 2.0. See `LICENSE.md`.

The vendored Falcon implementation under `src/zknox/falcon/` is from the Falcon team (Pornin et al.), released under MIT.

## References

### Falcon

- Prest, Fouque, Hoffstein, Kirchner, Lyubashevsky, Pornin, Ricosset, Seiler, Whyte, Zhang. _FALCON._ NIST PQC standardization, 2022. [Specification](https://falcon-sign.info/falcon.pdf)
- Howe, Prest, Ricosset, Rossi. _Isochronous Gaussian Sampling: From Inception to Implementation._ PQCrypto 2020. [eprint.iacr.org/2019/1411](https://eprint.iacr.org/2019/1411)

### Side-channel attacks on Falcon

- Karabulut, Aysu. _Falcon Down: Breaking Falcon Post-Quantum Signature Scheme through Side-Channel Attacks._ DAC 2021. [eprint.iacr.org/2021/772](https://eprint.iacr.org/2021/772)
- Guerreau, Martinelli, Ricosset, Rossi. _The Hidden Parallelepiped is Back Again: Power Analysis Attacks on Falcon._ TCHES 2022(3). [eprint.iacr.org/2022/057](https://eprint.iacr.org/2022/057)
- Zhang, Lin, Yu, Wang. _Improved Power Analysis Attacks on Falcon._ EUROCRYPT 2023. [eprint.iacr.org/2023/224](https://eprint.iacr.org/2023/224)
- Lin, Zhang, Yu, Wang, You, Xu, Wang. _Thorough Power Analysis on Falcon Gaussian Samplers and Practical Countermeasure._ PKC 2025. [eprint.iacr.org/2025/351](https://eprint.iacr.org/2025/351) · [code](https://github.com/lxhcrypto/FalconAnalysis)

### Hardware wallets and post-quantum

- Bos et al. _NTRU Prime: Reducing Attack Surface at Low Cost._ Selected Areas in Cryptography 2017. [eprint.iacr.org/2016/461](https://eprint.iacr.org/2016/461)
- Various NIST PQC standardization documents.

## Contact

ZKNOX SAS — Renaud, Nicolas, Simon. ZK + post-quantum security.
