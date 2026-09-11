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
#include "falcon_core.h"

#if FALCON_CORE_LOWRAM
/*
 * c-fn-dsa-alt core: one working area for keygen (22n+31) and sign (20n+31),
 * plus the encoded key emitted by the keygen (2369 + 1793 bytes for 1024),
 * kept at the end of the area. 27 648 bytes covers Falcon-1024.
 */
#define FALCON_LR_AREA_SIZE 27648
typedef struct {
    uint64_t area[FALCON_LR_AREA_SIZE / 8];
    uint8_t  out[41 + 2048];    /* 0x30+logn | nonce(40) | s2 raw int16 */
    uint8_t  msg[32];
    uint8_t  sign_seed[40];
    uint8_t  seed[32];          /* session seed (SLIP-10), never in NVM */
    uint8_t  seed_ready;        /* logn whose seed is cached, or 0 */
    uint8_t  msg_ready;
    uint8_t  sseed_ready;
    uint8_t  sig_ready;         /* logn of the signature in out[], or 0 */
} falcon_lr_storage_t;
extern falcon_lr_storage_t g_falcon_lr;
#endif

#if FALCON_CORE_LEGACY
#define FALCON_SIGN_BSS_SIZE 32768

typedef struct {
    /* The work area is used by both:
     *   - Falcon sign (sctx, ~28 KB).
     *   - Falcon keygen-expand (work_buf, exactly 32768 B = 4 × 8 KB).
     * Both ops are mutually exclusive in the host workflow. */
    uint64_t _falcon_sign_area[FALCON_SIGN_BSS_SIZE / 8];

    /* Falcon-1024 persistent. */
    uint8_t  falcon_seed[32];
    int8_t   falcon_f[1024];
    int8_t   falcon_g[1024];
    int8_t   falcon_F[1024];
    int8_t   falcon_G[1024];
    uint8_t  falcon_ready;
} zknox_storage_t;
extern zknox_storage_t g_zknox;
#endif /* FALCON_CORE_LEGACY */
