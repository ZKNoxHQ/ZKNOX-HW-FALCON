#pragma once
#include <stdint.h>
#include "ux.h"
#include "io.h"
#include "types.h"
#include "constants.h"

extern global_ctx_t G_context;
typedef struct internal_storage_t {
    uint8_t dummy1_allowed;
    uint8_t dummy2_allowed;
    uint8_t initialized;
} internal_storage_t;
extern const internal_storage_t N_storage_real;
#define N_storage (*(volatile internal_storage_t *) PIC(&N_storage_real))

#define SIG_MAX_SIZE 2420

/* v0.6.0 + Dilithium-stripped: Falcon-1024 only, no Dilithium / no hybrid.
 * The 32 KB sign area can grow to 32768 B (= 4 × 8 KB) to host the full
 * keygen-expand work_buf, since Dilithium globals are gone. */
#define FALCON_SIGN_BSS_SIZE 32768

typedef struct {
    /* The work area is used by both:
     *   - Falcon sign (sctx, ~28 KB).
     *   - Falcon keygen-expand (work_buf, exactly 32768 B = 4 × 8 KB).
     * Both ops are mutually exclusive in the host workflow. */
    uint64_t _falcon_sign_area[FALCON_SIGN_BSS_SIZE / 8];

    /* Falcon-1024 persistent secret material.
     *
     * NOTE: G is NOT stored — it is recomputed on demand from (f, g, F)
     * via Zf(complete_private) at the start of each keygen-expand and
     * sign operation. This saves 1024 B BSS (critical to keep the stack
     * budget above the Nano S+ minimum at ~1.5 KB). The recomputation
     * cost is roughly 50-100 ms per sign, ~1% overhead on the 8.5 s sign. */
    uint8_t  falcon_seed[32];
    int8_t   falcon_f[1024];
    int8_t   falcon_g[1024];
    int8_t   falcon_F[1024];
    /* int8_t falcon_G[1024];  -- removed, recomputed on demand */
    uint8_t  falcon_ready;
} zknox_storage_t;
extern zknox_storage_t g_zknox;
