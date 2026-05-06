/*
 * handler_falcon512_flash_sign.c — Falcon-512 flash variant — phase 2b (real sign)
 *
 * Duplicate of handler_falcon512_sign.c (streaming) with three changes:
 *   1. Tree material (L0 + DFS nodes) read from NVRAM via memcpy, not from
 *      host APDU + cx_outsourced_read_split. NVRAM is in the same TCB as the
 *      seed already, so encryption + MAC add no security property.
 *   2. The full sign sequence runs in ONE synchronous APDU (P1=0x10) once
 *      nonce + msg are loaded. Streaming has 6+ APDUs because of the
 *      FEED_TREE_STREAM/FEED_SWAP/GET_SWAP roundtrips needed when the host
 *      stores the encrypted blob; flash collapses them.
 *   3. z0 + z1 preserved on-device in fctx.z_pair_save (8 KB) — replaces
 *      the streaming roundtrip where the host buffers them between
 *      do_compute_s0_sqn and do_compute_s1_and_check.
 *
 * Helpers (dfs_enter, dfs_after_right, dfs_after_left, dfs_feed,
 * do_level0_enter, do_merge_right, do_after_right, do_merge_left,
 * do_compute_s0_sqn, do_compute_s1_and_check) copied verbatim from
 * streaming, with sctx → fctx (different struct alias, same memory).
 *
 * APDU contract (INS 0x63):
 *   P1=0x00:        INIT (reset fctx)
 *   P1=0x06 P2=0:   FEED_MSG  (cdata = 32 B msg)
 *   P1=0x08 P2=0:   FEED_NONCE_HOST (cdata = 40 B nonce)
 *   P1=0x09 P2=0:   GEN_NONCE_DEVICE (cdata = 0 B, uses TRNG)
 *   P1=0x10 P2=0:   SIGN_ALL (cdata = 0 B, runs full sign synchronously)
 *   P1=0x91 P2=0:   GET_NONCE (returns 40 B nonce used)
 *
 * INS 0x64 GET_SIG:
 *   P1 = chunk_idx, P2 = 0: returns up to 255 B of the 1024 B int16 sig
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
#include "handler_falcon512_flash_sign.h"
#include "falcon_inner.h"

#define FLOGN     9
#define FN        (1 << FLOGN)     /* 512 */
#define HN        (FN >> 1)        /* 256 */
#define DFS_LOGN  8

/* ===================================================================== *
 * Flash sign context — aliased onto _falcon_sign_area (same as streaming
 * sctx and keygen WORK_BUF; they are mutually non-concurrent).
 *
 * Field names match the streaming sctx where applicable, so the helper
 * functions copied below can be used unchanged after sctx → fctx renaming.
 *
 * NEW vs streaming:
 *   - z_pair_save[2*FN] (8 KB) — preserves z0+z1 across s0/s1 computations
 *     (replaces streaming's host roundtrip where the host buffers them).
 *
 * REMOVED vs streaming:
 *   - cx_outsourced_t outsourced  (no MAC verification on NVRAM reads)
 *   - uint8_t tag_buf[NODE_MAC_LEN]
 *   - size_t  accum_offset        (no host wire to accumulate)
 *   - inner_shake256_context _crypto_xof (only used in COMPUTE_HM, kept
 *                                         locally as an automatic var below)
 * ===================================================================== */
typedef struct {
    fpr stk[6 * HN];                  /* 12 KB DFS stack / level-0 workspace */
    fpr ws[HN];                        /* 2 KB DFS workspace per node */
    union {
        uint16_t hm[FN];                /* 1 KB hashed message */
        int16_t  sig[FN];               /* 1 KB signature (overlay) */
    } hm_sig;
    fpr z_pair_save[2 * FN];          /* 8 KB: z0+z1 preserved across s0/s1 */

    int phase;
    int depth, done;
    int child_phase[DFS_LOGN];

    sampler_context sc;

    int sig_valid;
    uint32_t sqn_saved;

    size_t tree_byte_offset;          /* current NVRAM read offset */

    /* Host inputs */
    uint8_t nonce[40];
    uint8_t msg[32];
    uint8_t nonce_set;
    uint8_t msg_set;
} falcon512_flash_sign_ctx_t;

#define fctx (*(falcon512_flash_sign_ctx_t *)(void *)g_zknox._falcon_sign_area)

_Static_assert(sizeof(falcon512_flash_sign_ctx_t) <= FALCON_SIGN_BSS_SIZE,
               "fctx exceeds _falcon_sign_area");

#define N_falcon_tree_512        ((const uint8_t *)PIC(N_falcon_tree_512_storage))
#define N_falcon_tree_512_ready  (*(const uint8_t *)PIC(&N_falcon_tree_512_ready_storage))

/* ===================================================================== *
 * DFS stack helpers (verbatim from streaming)
 * ===================================================================== */
static size_t foff(int d) { return 6 * (HN - (HN >> d)); }
static size_t psz(int d)  { return HN >> d; }
#define STK_LL(s,d)  ((s) + foff(d))
#define STK_T0(s,d)  ((s) + foff(d) + psz(d))
#define STK_T1(s,d)  ((s) + foff(d) + 2 * psz(d))

/* ===================================================================== *
 * Standard DFS (verbatim from streaming, sctx → fctx)
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
 * Level 0 operations (verbatim from streaming, sctx → fctx)
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

/* ===================================================================== *
 * Tree consumption from NVRAM (the single substitution vs streaming)
 *
 * Streaming: dfs_feed(ws) called after host APDU + verify + decrypt populated
 *            ws with the next plaintext node.
 * Flash:     dfs_feed(ws) called after memcpy(ws, NVRAM + offset, len).
 * Both consume the SAME plaintext bytes in the SAME order — the keygen-expand
 * walker on either variant emits in identical DFS order, so NVRAM byte i ==
 * streaming wire byte i (after streaming decryption + tag stripping).
 * ===================================================================== */
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

/* ===================================================================== *
 * Full synchronous sign — orchestrates the entire sequence in one APDU
 * ===================================================================== */
static uint16_t flash_sign_all(void) {
    if (!g_zknox.falcon_ready)        return SWO_INCORRECT_DATA;
    if (!fctx.nonce_set || !fctx.msg_set) return SWO_INCORRECT_DATA;

    /* 1. hash_to_point: hm = H(nonce || msg) */
    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, fctx.nonce, sizeof fctx.nonce);
    Zf(i_shake256_inject)(&xof, fctx.msg,   sizeof fctx.msg);
    Zf(i_shake256_flip)(&xof);
    Zf(hash_to_point_vartime)(&xof, fctx.hm_sig.hm, FLOGN);

    /* 2. compute_target — t0 at stk[0..FN-1], t1 at stk[FN..2*FN-1] */
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

    /* 3. Init sampler — same recipe as streaming COMPUTE_TARGET */
    inner_shake256_context srng;
    Zf(i_shake256_init)(&srng);
    Zf(i_shake256_inject)(&srng, g_zknox.falcon_seed, 32);
    Zf(i_shake256_inject)(&srng, (uint8_t *)fctx.hm_sig.hm, sizeof fctx.hm_sig.hm);
    Zf(i_shake256_flip)(&srng);
    fctx.sc.sigma_min = fpr_sigma_min_10;
    Zf(prng_init)(&fctx.sc.p, &srng);

    /* 4. do_level0_enter — uses t1 in stk[FN..2*FN-1] */
    do_level0_enter();

    /* 5. Consume right subtree from NVRAM[4096..22528) */
    fctx.tree_byte_offset = FN * sizeof(fpr);   /* 4096 (after L0) */
    consume_subtree_from_nvm();

    /* 6. do_merge_right → z1_merged at stk[0..FN-1] */
    do_merge_right();

    /* 7. Save z1 for s0/s1 computations later */
    memcpy(fctx.z_pair_save + FN, fctx.stk, FN * sizeof(fpr));

    /* 8. Recompute t1 + diff = t1 - z1_merged.
     *    Same code as streaming GET_SWAP transition. After this:
     *    - stk[0..FN-1]   = z1_merged (will be overwritten by L0 next)
     *    - stk[FN..2*FN-1]= diff
     *    - stk[2*FN..3*FN-1] = scratch (consumed) */
    {
        fpr *t1_re  = fctx.stk + FN;
        fpr *bufa   = fctx.stk + 2*FN;
        for (size_t u = 0; u < FN; u++) t1_re[u] = fpr_of(fctx.hm_sig.hm[u]);
        Zf(FFT)(t1_re, FLOGN);
        for (size_t u = 0; u < FN; u++) bufa[u]  = fpr_of(g_zknox.falcon_f[u]);
        Zf(FFT)(bufa, FLOGN); Zf(poly_neg)(bufa, FLOGN);
        Zf(poly_mul_fft)(t1_re, bufa, FLOGN);
        Zf(poly_mulconst)(t1_re, fpr_neg(ni), FLOGN);
        Zf(poly_sub)(t1_re, fctx.stk, FLOGN);   /* diff = t1 - z1_merged */
    }

    /* 9. Load L0 from NVRAM into stk[0..FN-1] (overwrites stale z1_merged) */
    memcpy(fctx.stk, N_falcon_tree_512, FN * sizeof(fpr));

    /* 10. do_after_right — consumes L0 + diff, sets up left-subtree DFS */
    do_after_right();

    /* 11. Consume left subtree from NVRAM[22528..40960) */
    fctx.tree_byte_offset = FN * sizeof(fpr) + 18432;   /* 4096 + 18432 = 22528 */
    consume_subtree_from_nvm();

    /* 12. do_merge_left → z0 at stk[0..FN-1] */
    do_merge_left();

    /* 13. Save z0 alongside the already-saved z1 → z_pair_save = [z0 | z1] */
    memcpy(fctx.z_pair_save, fctx.stk, FN * sizeof(fpr));

    /* 14. Bring z1 back into stk[FN..2*FN-1] for s0 computation */
    memcpy(fctx.stk + FN, fctx.z_pair_save + FN, FN * sizeof(fpr));

    /* 15. do_compute_s0_sqn — saves sqn, destroys stk content */
    do_compute_s0_sqn();

    /* 16. Restore z0 + z1 from z_pair_save for s1 computation */
    memcpy(fctx.stk, fctx.z_pair_save, 2 * FN * sizeof(fpr));

    /* 17. do_compute_s1_and_check — writes sig to fctx.hm_sig.sig, returns OK
     *     iff total norm (s0+s1) under bound */
    int ok = do_compute_s1_and_check();
    fctx.sig_valid = ok;

    return ok ? SWO_SUCCESS : SWO_INCORRECT_DATA;
}

/* ===================================================================== *
 * APDU handlers
 * ===================================================================== */

int handler_falcon512_flash_sign(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    switch (p1) {

    case 0x00:  /* INIT */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memset(&fctx, 0, sizeof(falcon512_flash_sign_ctx_t));
        return io_send_sw(SWO_SUCCESS);

    case 0x06:  /* FEED_MSG — 32-byte message digest */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.msg_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 32) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(fctx.msg, cdata->ptr, 32);
        fctx.msg_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x08:  /* FEED_NONCE_HOST — 40-byte salt (test mode) */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 40) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(fctx.nonce, cdata->ptr, 40);
        fctx.nonce_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x09:  /* GEN_NONCE_DEVICE — TRNG (production mode) */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        cx_rng_no_throw(fctx.nonce, 40);
        fctx.nonce_set = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x10: { /* SIGN_ALL — full synchronous sign (~1 sec) */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        if (N_falcon_tree_512_ready != 1) return io_send_sw(SWO_INCORRECT_DATA);
        uint16_t sw = flash_sign_all();
        return io_send_sw(sw);
    }

    case 0x91:  /* GET_NONCE — return the 40-B nonce used */
        if (p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (!fctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        io_send_response_pointer(fctx.nonce, 40, SWO_SUCCESS);
        return 0;

    default:
        return io_send_sw(SWO_INCORRECT_P1_P2);
    }
}


int handler_falcon512_flash_get_sig(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata; (void)p2;
    if (!fctx.sig_valid) return io_send_sw(SWO_INCORRECT_DATA);
    size_t total = FN * sizeof(int16_t);   /* 1024 */
    size_t off = (size_t)p1 * 255;
    if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
    size_t chunk = total - off; if (chunk > 255) chunk = 255;
    io_send_response_pointer(((uint8_t *)fctx.hm_sig.sig) + off, chunk, SWO_SUCCESS);
    return 0;
}
