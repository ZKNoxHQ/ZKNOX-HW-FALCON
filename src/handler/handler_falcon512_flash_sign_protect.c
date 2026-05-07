/*
 * handler_falcon512_flash_sign_protect.c — SCA-protected Falcon-512 flash sign
 *
 * INS 0x66 (mirrors INS 0x63's APDU contract).
 *
 * The sampler's 1.2 KB workspace lives INSIDE fctx (no extra BSS) — fctx
 * aliases onto _falcon_sign_area which has ~8 KB of headroom after the
 * existing fields. flash512_sign_all_protect sets the global pointer used
 * by sampler_protect right before the sign starts.
 *
 * Algorithmic difference vs unprotected sign: dfs_feed at leaves calls
 * sampler_protect (Lin et al. PKC 2025 Algos 5/6/7) instead of Zf(sampler).
 * Everything else identical.
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

#include "handler_falcon512_flash.h"
#include "handler_falcon512_flash_sign_protect.h"
#include "falcon_inner.h"
#include "../zknox/falcon/falcon_sampler_protect.h"

#define FLOGN     9
#define FN        512
#define HN        256
#define DFS_LOGN  8

typedef struct {
    fpr stk[6 * HN];                          /* 12 KB */
    fpr ws[HN];                                /* 2 KB */
    union {
        uint16_t hm[FN];                        /* 1 KB */
        int16_t  sig[FN];
    } hm_sig;
    fpr z_pair_save[2 * FN];                   /* 8 KB */
    falcon_sampler_protect_ws_t protect_ws;    /* 1.2 KB — sampler scratch
                                                * inside fctx, no extra BSS */

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
} falcon_flash_sign_ctx_t;

#define fctx (*(falcon_flash_sign_ctx_t *)(void *)g_zknox._falcon_sign_area)

_Static_assert(sizeof(falcon_flash_sign_ctx_t) <= FALCON_SIGN_BSS_SIZE,
               "Falcon-512 protected fctx exceeds _falcon_sign_area");

#define N_falcon_tree_512        ((const uint8_t *)PIC(N_falcon_tree_512_storage))
#define N_falcon_tree_512_ready  (*(const uint8_t *)PIC(&N_falcon_tree_512_ready_storage))

/* ===================================================================== *
 * DFS stack helpers
 * ===================================================================== */
static size_t foff(int d) { return 6 * (HN - (HN >> d)); }
static size_t psz(int d)  { return HN >> d; }
#define STK_LL(s,d)  ((s) + foff(d))
#define STK_T0(s,d)  ((s) + foff(d) + psz(d))
#define STK_T1(s,d)  ((s) + foff(d) + 2 * psz(d))

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

/* The single algorithmic difference with the unprotected handler: */
static int dfs_feed(const fpr *data) {
    int dep = fctx.depth;
    if (dep >= DFS_LOGN) {
        fpr *pt0=STK_T0(fctx.stk,dep),*pt1=STK_T1(fctx.stk,dep);
        pt0[0]=fpr_of(sampler_protect(&fctx.sc,pt0[0],data[0]));
        pt1[0]=fpr_of(sampler_protect(&fctx.sc,pt1[0],data[0]));
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
 * Level 0 ops + s0/s1
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

static void do_compute_s0_sqn(void) {
    fpr *z0 = fctx.stk;
    fpr *z1 = fctx.stk + FN;
    fpr *buf = fctx.stk + 2*FN;

    int8_t G_local[FN];
    Zf(complete_private)(G_local,
                         g_zknox.falcon_f, g_zknox.falcon_g,
                         g_zknox.falcon_F, FLOGN, (uint8_t *)fctx.ws);

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_g[u]);
    Zf(FFT)(buf, FLOGN);
    Zf(poly_mul_fft)(z0, buf, FLOGN);

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(G_local[u]);
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

static void consume_subtree_from_nvm(void) {
    while (!fctx.done) {
        int dep = fctx.depth;
        size_t node_bytes = (dep >= DFS_LOGN)
                            ? sizeof(fpr)
                            : psz(dep) * sizeof(fpr);
        memcpy(fctx.ws,
               N_falcon_tree_512 + fctx.tree_byte_offset,
               node_bytes);
        fctx.tree_byte_offset += node_bytes;
        dfs_feed((const fpr *)fctx.ws);
    }
}

#define L0_BYTES_512            (FN * sizeof(fpr))
#define SUBTREE_BYTES_512       18432UL
#define LEFT_SUBTREE_OFFSET_512 (L0_BYTES_512 + SUBTREE_BYTES_512)

/* ===================================================================== *
 * Full synchronous sign
 * ===================================================================== */
static uint16_t flash512_sign_all_protect(void) {
    if (!g_zknox.falcon_ready)             return SWO_INCORRECT_DATA;
    if (!fctx.nonce_set || !fctx.msg_set)  return SWO_INCORRECT_DATA;

    /* Point sampler_protect at the workspace inside fctx — no extra BSS. */
    g_falcon_sampler_protect_ws = &fctx.protect_ws;

    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, fctx.nonce, sizeof fctx.nonce);
    Zf(i_shake256_inject)(&xof, fctx.msg,   sizeof fctx.msg);
    Zf(i_shake256_flip)(&xof);
    Zf(hash_to_point_vartime)(&xof, fctx.hm_sig.hm, FLOGN);

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

    inner_shake256_context srng;
    Zf(i_shake256_init)(&srng);
    Zf(i_shake256_inject)(&srng, g_zknox.falcon_seed, 32);
    Zf(i_shake256_inject)(&srng, (uint8_t *)fctx.hm_sig.hm, sizeof fctx.hm_sig.hm);
    Zf(i_shake256_flip)(&srng);
    fctx.sc.sigma_min = fpr_sigma_min_10;
    Zf(prng_init)(&fctx.sc.p, &srng);

    do_level0_enter();

    fctx.tree_byte_offset = L0_BYTES_512;
    consume_subtree_from_nvm();

    do_merge_right();

    memcpy(fctx.z_pair_save + FN, fctx.stk, FN * sizeof(fpr));

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

    memcpy(fctx.stk, N_falcon_tree_512, FN * sizeof(fpr));

    do_after_right();

    fctx.tree_byte_offset = LEFT_SUBTREE_OFFSET_512;
    consume_subtree_from_nvm();

    do_merge_left();

    memcpy(fctx.z_pair_save, fctx.stk, FN * sizeof(fpr));

    memcpy(fctx.stk + FN, fctx.z_pair_save + FN, FN * sizeof(fpr));

    do_compute_s0_sqn();

    memcpy(fctx.stk, fctx.z_pair_save, 2 * FN * sizeof(fpr));

    int ok = do_compute_s1_and_check();
    fctx.sig_valid = ok;

    return ok ? SWO_SUCCESS : SWO_INCORRECT_DATA;
}

/* ===================================================================== *
 * APDU handler — INS 0x66
 * ===================================================================== */
int handler_falcon512_flash_sign_protect(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    switch (p1) {

    case 0x00:
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memset(&fctx, 0, sizeof(falcon_flash_sign_ctx_t));
        return io_send_sw(SWO_SUCCESS);

    case 0x06:
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.msg_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 32) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(fctx.msg, cdata->ptr, 32);
        fctx.msg_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x08:
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 40) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(fctx.nonce, cdata->ptr, 40);
        fctx.nonce_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x09:
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        cx_rng_no_throw(fctx.nonce, 40);
        fctx.nonce_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x10: {
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        if (N_falcon_tree_512_ready != 1) return io_send_sw(SWO_INCORRECT_DATA);
        uint16_t sw = flash512_sign_all_protect();
        return io_send_sw(sw);
    }

    case 0x91:
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (!fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        io_send_response_pointer(fctx.nonce, 40, SWO_SUCCESS);
        return 0;

    default:
        return io_send_sw(SWO_INCORRECT_P1_P2);
    }
}
