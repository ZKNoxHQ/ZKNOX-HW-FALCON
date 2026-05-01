# Option A v0.1.1 — drop G from BSS, recompute on demand (FIXED)

Saves 1024 B BSS. Free RAM goes from 1556 B to 2580 B.

## Bug fix vs v0.1.0

v0.1.0 added `int8_t G_recomputed[FN]` as a struct field at the end of
`falcon1024_sign_ctx_t`. The struct already had ~31.5 KB of headroom inside
`_falcon_sign_area` (32 KB). Adding 1024 B made it overflow by ~192 B,
which corrupted `g_zknox.falcon_seed` at every sign INIT (`memset(&sctx, 0,
sizeof(struct))` zeroed not just `_falcon_sign_area` but also the seed
following it in BSS layout).

→ Symptom: `KEYGEN` + `KEYGEN_EXPAND` worked correctly (didn't touch the
seed), but `SIGN` corrupted the seed at INIT. The L0 MAC verification at
the start of the LDL feed used the corrupted seed → MAC failed →
SW=b00a (`SWO_TREE_MAC_FAIL`).

## Fix in v0.1.1

Don't add G_recomputed to the struct. Instead, allocate G_local on the
stack inside `do_compute_s0_sqn`, the only function that uses G during sign:

```c
static void do_compute_s0_sqn(void) {
    fpr *z0 = sctx.stk;
    fpr *z1 = sctx.stk + FN;
    fpr *buf = sctx.stk + 2*FN;

    int8_t G_local[FN];   /* 1 KB stack */
    Zf(complete_private)(G_local, falcon_f, falcon_g, falcon_F, FLOGN,
                         (uint8_t *)sctx.ws);   /* uses sctx.ws as 4 KB tmp */

    /* ... use G_local as before ... */
}
```

`do_compute_s0_sqn` is called from a flat dispatcher path, so stack
budget at call time is fresh (~2 KB available). `G_local[1024]` (1 KB)
plus complete_private internal frames (negligible) fits.

## Files modified vs original v0.7.0

| File                                              | Status |
|---------------------------------------------------|--------|
| `src/globals.h`                                   | UPDATE — drops `falcon_G[1024]` from `zknox_storage_t` |
| `src/falcon_inner.h`                              | UPDATE — adds `falcon_complete_private` alias |
| `src/handler/handler_falcon.c`                    | UPDATE — keygen writes G into ephemeral buffer in `_falcon_sign_area` |
| `src/handler/handler_falcon_keygen_expand.c`      | UPDATE — `gram_phase()` takes G as parameter; `compute_l0_phase()` recomputes G via complete_private |
| `src/handler/handler_falcon_sign.c`               | UPDATE — `do_compute_s0_sqn` recomputes G into stack `G_local[FN]` |
| `src/handler/handler_falcon512.c`                 | UPDATE — same pattern as falcon-1024 keygen |
| `src/handler/handler_falcon512_keygen_expand.c`   | UPDATE — same pattern as falcon-1024 keygen_expand |
| `src/handler/handler_falcon512_sign.c`            | UPDATE — same pattern as falcon-1024 sign |

## Performance impact

`complete_private` ≈ 50-100 ms on Nano S+ for Falcon-1024, ~25-50 ms for
Falcon-512. Adds ~1% to sign duration; ~0.5% to keygen_expand duration.

## Stack usage

| Function | Stack added |
|----------|------------:|
| `compute_l0_phase`  | 1024 B (G_buf) for Falcon-1024, 512 B for Falcon-512 |
| `do_compute_s0_sqn` | 1024 B (G_local) for Falcon-1024, 512 B for Falcon-512 |

Both are isolated paths (no overlap with deep recursion). Free RAM after
v0.1.1 patch ≈ 2580 B, comfortably above the 1024 B Nano S+ minimum.
