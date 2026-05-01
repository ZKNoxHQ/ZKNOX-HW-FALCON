# Setup notes — Falcon-512 v0.1.1

This package adds Falcon-512 alongside Falcon-1024 in the same firmware,
without touching any existing v0.7.0 file. New INS codes:

| INS  | Name                       | Pairs with                |
|-----:|----------------------------|---------------------------|
| 0x40 | `FALCON512_KEYGEN`         | 0x30 `FALCON_KEYGEN`      |
| 0x41 | `FALCON512_GET_PK`         | 0x31 `FALCON_GET_PK`      |
| 0x43 | `FALCON512_SIGN`           | 0x33 `FALCON_SIGN`        |
| 0x44 | `FALCON512_KEYGEN_EXPAND`  | 0x34 `FALCON_KEYGEN_EXPAND` |

## File deployment

Files in this package mirror your repo structure. Copy with:

```bash
cp -r falcon512_v011/src .
cp -r falcon512_v011/js .
cp -r falcon512_v011/tools .
cp falcon512_v011/Makefile .
```

That copies:

| File                                              | Status |
|---------------------------------------------------|--------|
| `src/handler/handler_falcon512.c`                 | NEW    |
| `src/handler/handler_falcon512.h`                 | NEW    |
| `src/handler/handler_falcon512_sign.c`            | NEW    |
| `src/handler/handler_falcon512_sign.h`            | NEW    |
| `src/handler/handler_falcon512_keygen_expand.c`   | NEW    |
| `src/handler/handler_falcon_keygen_expand.c`      | UPDATE — `static` removed from `g_kstate` (1 line) |
| `src/handler/handler_falcon512_keygen_expand.h`   | NEW    |
| `src/zknox/keys/derive_falcon512.c`               | NEW    |
| `src/apdu/dispatcher.c`                           | UPDATE — adds 4 case branches |
| `src/types.h`                                     | UPDATE — adds 4 enum entries  |
| `Makefile`                                        | UPDATE — removes Dilithium, adds `make docker` target |

**Only one v0.7.0 file is touched, with a 1-line change:**
- `src/handler/handler_falcon_keygen_expand.c` — removes `static` from
  `g_kstate` declaration. This makes the persistent walker state symbol
  visible to the linker so Falcon-512 can share it via `extern` (saves
  ~250 B BSS, critical to stay under the Nano S+ stack limit).

No other v0.7.0 file is changed:
- `src/globals.h` ✅
- `src/falcon_inner.h` ✅
- `src/handler/handler_falcon.{c,h}` ✅
- `src/handler/handler_falcon_sign.{c,h}` ✅
- `src/handler/handler_falcon_keygen_expand.h` ✅
- `src/zknox/keys/derive.c` ✅

## `src/types.h`

The included `src/types.h` is your existing file with four entries added
to the `command_e` enum (plus a comma fix on the previously-last entry).
Diff before overwriting to be sure:

```bash
diff src/types.h falcon512_v011/src/types.h
```

You should see only these additions:

```c
+    FALCON_KEYGEN_EXPAND = 0x34,    (← comma added)
+    /* Falcon-512 post-quantum signature (v0.1.0) */
+    FALCON512_KEYGEN = 0x40,        /// Falcon-512 keygen
+    FALCON512_GET_PK = 0x41,        /// retrieve Falcon-512 public key chunks
+    FALCON512_SIGN = 0x43,          /// iterative Falcon-512 sign
+    FALCON512_KEYGEN_EXPAND = 0x44  /// stream Falcon-512 wire blob
```

If the diff shows anything else (entries you've added since the version
I had visibility into), don't blindly overwrite — manually add the four
`FALCON512_*` entries to your existing enum body.

## Build & test

```bash
# Enter the Ledger build container (replaces docker.sh — path-independent)
make docker

# Inside the container:
make clean && make load
exit

# Test Falcon-1024 still works (regression check)
cd js
node falcon1024-full-chain.js
# Expected: pk SHA-256 = abda0932...
#           wire SHA-256 = 855edeed...

# Test Falcon-512
node falcon512-full-chain.js
# Expected: pk SHA-256 = f3c31b60497fbac856b8c062ef314db2106755356dbd9777d4bff8b03ea9914e
#           wire SHA-256 = 762097cdab496d2c4c39d80e2751e35b77ebbd8ae19e11e2d4ef738a1c7737c5
```

## Notes

- **g_zknox storage is shared.** `KEYGEN` (Falcon-1024) and `FALCON512_KEYGEN`
  both write into `g_zknox.falcon_seed/f/g/F/G/h`. Calling one overwrites the
  other. There is one active key at a time.
- **`falcon_ready` is shared too.** After any KEYGEN, both variants think
  they have a key. Calling `FALCON_GET_PK` after `FALCON512_KEYGEN` will
  return Falcon-512 bytes — wrong format. Don't mix calls between variants
  without re-keygen.
- **The arrays `falcon_f/g/F/G[1024]` are oversized for Falcon-512.**
  Falcon-512 only fills the first 512 bytes. The other 512 bytes are stale
  Falcon-1024 data (or zeros after first call). This is harmless because
  Falcon-512 sign/expand only reads indices [0..511].
- **`_falcon_sign_area` is 32 KB** — sized for Falcon-1024. Falcon-512 uses
  ~16 KB of it during keygen-expand. Plenty of room.
- **JS files are in `js/`**, generated testvecs `falcon512_yellow12_*.bin`
  reference values in there.
- The `tools/wire_sim.c` source is included so you can regenerate testvecs
  if needed (compile against Falcon reference impl with `-DFALCON_VARIANT=512`).

