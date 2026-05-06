/*
 * handler_falcon1024_flash_sign.c — Falcon-1024 flash variant — real sign
 *
 * G is in NVRAM (persisted at keygen) — read directly via PIC, no
 * complete_private call here. This avoids both:
 *   - stack-heavy `int8_t G[FN]` (1024 B + complete_private internal locals
 *     overflow the BOLOS app stack on Nano S+)
 *   - BSS-heavy alternative (linker squeezes the .stack section)
 *
 * z0 + z1 are written to NVRAM scratchpad (N_falcon_zscratch_1024) and read
 * back when needed for s0 / s1 computation. Two NVRAM writes per sign
 * (~80 ms each), total sign ~2.5 sec on Nano S+.
 *
 * APDU contract (INS 0x73):
 *   P1=0x00:        INIT (reset fctx)
 *   P1=0x06 P2=0:   FEED_MSG  (cdata = 32 B msg)
 *   P1=0x08 P2=0:   FEED_NONCE_HOST (cdata = 40 B nonce)
 *   P1=0x09 P2=0:   GEN_NONCE_DEVICE (cdata = 0 B, uses TRNG)
 *   P1=0x10 P2=0:   SIGN_ALL (cdata = 0 B, runs full sign synchronously)
 *   P1=0x91 P2=0:   GET_NONCE (returns 40 B nonce used)
 *
 * INS 0x74 GET_SIG: chunked retrieval of int16[1024] = 2048 B sig
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../sw.h"
#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "../globals.h"
#include "send_response.h"

#include "handler_falcon1024_flash.h"
#include "handler_falcon1024_flash_sign.h"
#include "falcon_inner.h"

#define FLOGN     10
#define FN        1024
#define HN        512
#define DFS_LOGN  9

/* ===================================================================== *
 * Flash sign context — aliased onto _falcon_sign_area.
 * No z_pair_save (NVRAM scratchpad), no G storage (NVRAM).
 * ===================================================================== */
typedef struct {
    fpr stk[6 * HN];                  /* 24 KB DFS stack */
    fpr ws[HN];                        /* 4 KB DFS workspace per node */
    union {
        uint16_t hm[FN];                /* 2 KB hashed message */
        int16_t  sig[FN];               /* 2 KB signature (overlay) */
    } hm_sig;

    int phase;
    int depth, done;
    int child_phase[DFS_LOGN];

    sampler_context sc;

    int sig_valid;
    uint32_t sqn_saved;

    size_t tree_byte_offset;

    uint8_t nonce[40];
    uint8_t msg[32];
    uint8_t nonce_set;
    uint8_t msg_set;
} falcon1024_flash_sign_ctx_t;

#define fctx (*(falcon1024_flash_sign_ctx_t *)(void *)g_zknox._falcon_sign_area)

_Static_assert(sizeof(falcon1024_flash_sign_ctx_t) <= FALCON_SIGN_BSS_SIZE,
               "Falcon-1024 fctx exceeds _falcon_sign_area");

#define N_falcon_tree_1024        ((const uint8_t *)PIC(N_falcon_tree_1024_storage))
#define N_falcon_G_1024           ((const int8_t  *)PIC(N_falcon_G_1024_storage))
#define N_falcon_zscratch_1024    ((const uint8_t *)PIC(N_falcon_zscratch_1024_storage))
#define N_falcon_tree_1024_ready  (*(const uint8_t *)PIC(&N_falcon_tree_1024_ready_storage))

/* ===================================================================== *
 * DFS stack helpers
 * ===================================================================== */
static size_t foff(int d) { return 6 * (HN - (HN >> d)); }
static size_t psz(int d)  { return HN >> d; }
#define STK_LL(s,d)  ((s) + foff(d))
#define STK_T0(s,d)  ((s) + foff(d) + psz(d))
#define STK_T1(s,d)  ((s) + foff(d) + 2 * psz(d))

/* ===================================================================== *
 * Standard DFS
 * ===================================================================== */
static void dfs_enter(int dep) {
    unsigned ln = DFS_LOGN - dep;
    Zf(poly_split_fft)(STK_T0(fctx.stk, dep+1), STK_T1(fctx.stk, dep+1),
                       STK_T1(fctx.stk, dep), ln);
    fctx.child_phase[dep] = 0;
}

static void dfs_after_right(int dep) {
    size_t m = psz(dep); unsigned ln = DFS_LOGN - dep;
    fpr *pL=STK_LL(fctx.stk,dep),*pt0=STK_T0(fctx.stk,dep),*pt1=STK_T1(fctx.stk,dep);
    fpr *c0=STK_T0(fctx.stk,dep+1),*c1=STK_T1(fctx.stk,dep+1);
    memcpy(fctx.ws,pt1,m*sizeof(fpr));
    Zf(poly_merge_fft)(pt1,c0,c1,ln);
    Zf(poly_sub)(fctx.ws,pt1,ln);
    Zf(poly_mul_fft)(fctx.ws,pL,ln);
    Zf(poly_add)(fctx.ws,pt0,ln);
    Zf(poly_split_fft)(STK_T0(fctx.stk,dep+1),STK_T1(fctx.stk,dep+1),fctx.ws,ln);
    fctx.child_phase[dep] = 1;
}

static void dfs_after_left(int dep) {
    unsigned ln = DFS_LOGN - dep;
    Zf(poly_merge_fft)(fctx.ws,STK_T0(fctx.stk,dep+1),STK_T1(fctx.stk,dep+1),ln);
    if (dep == 0) { /* z_half in ws, z1_half in STK_T1(0) */ }
    else memcpy(STK_T0(fctx.stk,dep),fctx.ws,psz(dep)*sizeof(fpr));
}

static int dfs_feed(const fpr *data) {
    int dep = fctx.depth;
    if (dep >= DFS_LOGN) {
        fpr *pt0=STK_T0(fctx.stk,dep),*pt1=STK_T1(fctx.stk,dep);
        pt0[0]=fpr_of(Zf(sampler)(&fctx.sc,pt0[0],data[0]));
        pt1[0]=fpr_of(Zf(sampler)(&fctx.sc,pt1[0],data[0]));
        for(;;){
            if(dep==0){fctx.done=1;return 1;} dep--;
            if(fctx.child_phase[dep]==0){dfs_after_right(dep);fctx.depth=dep+1;return 0;}
            else dfs_after_left(dep);
        }
    } else {
        memcpy(STK_LL(fctx.stk,dep),data,psz(dep)*sizeof(fpr));
        dfs_enter(dep); fctx.depth=dep+1; return 0;
    }
}

/* ===================================================================== *
 * Level 0 operations
 * ===================================================================== */
static void do_level0_enter(void) {
    memcpy(fctx.stk + 2*FN, fctx.stk + FN, FN * sizeof(fpr));
    Zf(poly_split_fft)(STK_T0(fctx.stk, 0), STK_T1(fctx.stk, 0),
                       fctx.stk + 2*FN, FLOGN);
    fctx.depth = 0; fctx.done = 0;
    memset(fctx.child_phase, 0, sizeof fctx.child_phase);
}

static void do_merge_right(void) {
    fpr *z0_right = fctx.ws;
    fpr *z1_right = STK_T1(fctx.stk, 0);
    Zf(poly_merge_fft)(fctx.stk, z0_right, z1_right, FLOGN);
}

static void do_after_right(void) {
    fpr *L0   = fctx.stk;
    fpr *diff = fctx.stk + FN;
    fpr *buf  = fctx.stk + 2*FN;
    fpr ni = fpr_inverse_of_q;

    Zf(poly_mul_fft)(diff, L0, FLOGN);

    fpr *t0_recalc = L0;
    for (size_t u = 0; u < FN; u++) t0_recalc[u] = fpr_of(fctx.hm_sig.hm[u]);
    Zf(FFT)(t0_recalc, FLOGN);
    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_F[u]);
    Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
    Zf(poly_mul_fft)(t0_recalc, buf, FLOGN);
    Zf(poly_mulconst)(t0_recalc, ni, FLOGN);

    Zf(poly_add)(t0_recalc, diff, FLOGN);

    memcpy(fctx.stk + 2*FN, t0_recalc, FN * sizeof(fpr));
    Zf(poly_split_fft)(STK_T0(fctx.stk, 0), STK_T1(fctx.stk, 0),
                       fctx.stk + 2*FN, FLOGN);

    fctx.depth = 0; fctx.done = 0;
    memset(fctx.child_phase, 0, sizeof fctx.child_phase);
}

static void do_merge_left(void) {
    fpr *z0_left = fctx.ws;
    fpr *z1_left = STK_T1(fctx.stk, 0);
    Zf(poly_merge_fft)(fctx.stk, z0_left, z1_left, FLOGN);
}

static int do_compute_s1_and_check(void) {
    fpr *z0 = fctx.stk;
    fpr *z1 = fctx.stk + FN;
    fpr *buf = fctx.stk + 2*FN;

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_f[u]);
    Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
    Zf(poly_mul_fft)(z0, buf, FLOGN);

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_F[u]);
    Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
    Zf(poly_mul_fft)(z1, buf, FLOGN);

    Zf(poly_add)(z0, z1, FLOGN);
    Zf(iFFT)(z0, FLOGN);

    for (size_t u = 0; u < FN; u++)
        fctx.hm_sig.sig[u] = (int16_t)-fpr_rint(z0[u]);

    return Zf(is_short_half)(fctx.sqn_saved, fctx.hm_sig.sig, FLOGN);
}

/* G read directly from NVRAM (saved at keygen) — no complete_private */
static void do_compute_s0_sqn(void) {
    fpr *z0 = fctx.stk;
    fpr *z1 = fctx.stk + FN;
    fpr *buf = fctx.stk + 2*FN;

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_g[u]);
    Zf(FFT)(buf, FLOGN);
    Zf(poly_mul_fft)(z0, buf, FLOGN);

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(N_falcon_G_1024[u]);
    Zf(FFT)(buf, FLOGN);
    Zf(poly_mul_fft)(z1, buf, FLOGN);

    Zf(poly_add)(z0, z1, FLOGN);
    Zf(iFFT)(z0, FLOGN);

    uint32_t sqn = 0, ng = 0;
    for (size_t u = 0; u < FN; u++) {
        int32_t z = (int32_t)fctx.hm_sig.hm[u] - (int32_t)fpr_rint(z0[u]);
        sqn += (uint32_t)(z * z); ng |= sqn;
    }
    sqn |= -(ng >> 31);
    fctx.sqn_saved = sqn;
}

/* ===================================================================== *
 * Tree consumption from NVRAM
 * ===================================================================== */
static void consume_subtree_from_nvm(void) {
    while (!fctx.done) {
        int dep = fctx.depth;
        size_t node_bytes = (dep >= DFS_LOGN)
                            ? sizeof(fpr)
                            : psz(dep) * sizeof(fpr);
        memcpy(fctx.ws,
               N_falcon_tree_1024 + fctx.tree_byte_offset,
               node_bytes);
        fctx.tree_byte_offset += node_bytes;
        dfs_feed((const fpr *)fctx.ws);
    }
}

/* Tree byte offsets:
 *   L0           : [0, 8192)
 *   right subtree: [8192, 49152)
 *   left  subtree: [49152, 90112)
 */
#define L0_BYTES_1024            (FN * sizeof(fpr))   /* 8192 */
#define SUBTREE_BYTES_1024       40960UL
#define LEFT_SUBTREE_OFFSET_1024 (L0_BYTES_1024 + SUBTREE_BYTES_1024)  /* 49152 */

/* ===================================================================== *
 * Full synchronous sign
 * ===================================================================== */
static uint16_t flash1024_sign_all(void) {
    if (!g_zknox.falcon_ready)             return SWO_INCORRECT_DATA;
    if (!fctx.nonce_set || !fctx.msg_set)  return SWO_INCORRECT_DATA;

    /* 1. hash_to_point */
    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, fctx.nonce, sizeof fctx.nonce);
    Zf(i_shake256_inject)(&xof, fctx.msg,   sizeof fctx.msg);
    Zf(i_shake256_flip)(&xof);
    Zf(hash_to_point_vartime)(&xof, fctx.hm_sig.hm, FLOGN);

    /* 2. compute_target */
    fpr *t0 = fctx.stk;
    fpr *t1 = fctx.stk + FN;
    fpr *buf = fctx.stk + 2*FN;
    fpr ni = fpr_inverse_of_q;

    for (size_t u = 0; u < FN; u++) t0[u] = fpr_of(fctx.hm_sig.hm[u]);
    Zf(FFT)(t0, FLOGN); memcpy(t1, t0, FN * sizeof(fpr));

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_f[u]);
    Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
    Zf(poly_mul_fft)(t1, buf, FLOGN);
    Zf(poly_mulconst)(t1, fpr_neg(ni), FLOGN);

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_F[u]);
    Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
    Zf(poly_mul_fft)(t0, buf, FLOGN);
    Zf(poly_mulconst)(t0, ni, FLOGN);

    /* 3. Init sampler */
    inner_shake256_context srng;
    Zf(i_shake256_init)(&srng);
    Zf(i_shake256_inject)(&srng, g_zknox.falcon_seed, 32);
    Zf(i_shake256_inject)(&srng, (uint8_t *)fctx.hm_sig.hm, sizeof fctx.hm_sig.hm);
    Zf(i_shake256_flip)(&srng);
    fctx.sc.sigma_min = fpr_sigma_min_10;
    Zf(prng_init)(&fctx.sc.p, &srng);

    /* 4. do_level0_enter */
    do_level0_enter();

    /* 5. Consume right subtree from NVRAM[8192..49152) */
    fctx.tree_byte_offset = L0_BYTES_1024;
    consume_subtree_from_nvm();

    /* 6. do_merge_right → z1 at stk[0..FN-1] */
    do_merge_right();

    /* 7. NVRAM-WRITE z1 → scratchpad[FN..2*FN-1] */
    nvm_write((void *)(N_falcon_zscratch_1024 + FN * sizeof(fpr)),
              (uint8_t *)fctx.stk,
              FN * sizeof(fpr));

    /* 8. Recompute t1 + diff = t1 - z1_merged */
    {
        fpr *t1_re  = fctx.stk + FN;
        fpr *bufa   = fctx.stk + 2*FN;
        for (size_t u = 0; u < FN; u++) t1_re[u] = fpr_of(fctx.hm_sig.hm[u]);
        Zf(FFT)(t1_re, FLOGN);
        for (size_t u = 0; u < FN; u++) bufa[u]  = fpr_of(g_zknox.falcon_f[u]);
        Zf(FFT)(bufa, FLOGN); Zf(poly_neg)(bufa, FLOGN);
        Zf(poly_mul_fft)(t1_re, bufa, FLOGN);
        Zf(poly_mulconst)(t1_re, fpr_neg(ni), FLOGN);
        Zf(poly_sub)(t1_re, fctx.stk, FLOGN);
    }

    /* 9. Load L0 from NVRAM tree[0..FN-1] into stk[0..FN-1] */
    memcpy(fctx.stk, N_falcon_tree_1024, FN * sizeof(fpr));

    /* 10. do_after_right */
    do_after_right();

    /* 11. Consume left subtree from NVRAM[49152..90112) */
    fctx.tree_byte_offset = LEFT_SUBTREE_OFFSET_1024;
    consume_subtree_from_nvm();

    /* 12. do_merge_left → z0 at stk[0..FN-1] */
    do_merge_left();

    /* 13. NVRAM-WRITE z0 → scratchpad[0..FN-1] */
    nvm_write((void *)N_falcon_zscratch_1024,
              (uint8_t *)fctx.stk,
              FN * sizeof(fpr));

    /* 14. NVRAM-READ z1 into stk[FN..2*FN-1] */
    memcpy(fctx.stk + FN,
           N_falcon_zscratch_1024 + FN * sizeof(fpr),
           FN * sizeof(fpr));

    /* 15. do_compute_s0_sqn */
    do_compute_s0_sqn();

    /* 16. NVRAM-READ z0 + z1 */
    memcpy(fctx.stk,
           N_falcon_zscratch_1024,
           2 * FN * sizeof(fpr));

    /* 17. do_compute_s1_and_check */
    int ok = do_compute_s1_and_check();
    fctx.sig_valid = ok;

    return ok ? SWO_SUCCESS : SWO_INCORRECT_DATA;
}

/* ===================================================================== *
 * APDU handlers
 * ===================================================================== */

int handler_falcon1024_flash_sign(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    switch (p1) {

    case 0x00:  /* INIT */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memset(&fctx, 0, sizeof(falcon1024_flash_sign_ctx_t));
        return io_send_sw(SWO_SUCCESS);

    case 0x06:  /* FEED_MSG */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.msg_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 32) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(fctx.msg, cdata->ptr, 32);
        fctx.msg_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x08:  /* FEED_NONCE_HOST */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 40) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(fctx.nonce, cdata->ptr, 40);
        fctx.nonce_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x09:  /* GEN_NONCE_DEVICE */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        cx_rng_no_throw(fctx.nonce, 40);
        fctx.nonce_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x10: { /* SIGN_ALL */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        if (N_falcon_tree_1024_ready != 1) return io_send_sw(SWO_INCORRECT_DATA);
        uint16_t sw = flash1024_sign_all();
        return io_send_sw(sw);
    }

    case 0x91:  /* GET_NONCE */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (!fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        io_send_response_pointer(fctx.nonce, 40, SWO_SUCCESS);
        return 0;

    default:
        return io_send_sw(SWO_INCORRECT_P1_P2);
    }
}


int handler_falcon1024_flash_get_sig(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata; (void)p2;
    if (!fctx.sig_valid) return io_send_sw(SWO_INCORRECT_DATA);
    size_t total = FN * sizeof(int16_t);
    size_t off = (size_t)p1 * 255;
    if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
    size_t chunk = total - off; if (chunk > 255) chunk = 255;
    io_send_response_pointer(((uint8_t *)fctx.hm_sig.sig) + off, chunk, SWO_SUCCESS);
    return 0;
}
