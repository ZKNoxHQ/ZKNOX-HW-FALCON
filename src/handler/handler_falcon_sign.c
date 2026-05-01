/*
 * handler_falcon_sign.c — Falcon-1024 sign for Ledger Nano S Plus
 *
 * Level 0 (1024-element polys): manual host-assisted swap
 * Levels 1-10 (512..1 elements): standard DFS (= Falcon-512 code)
 * Same stk[3072 fpr] buffer reused for both phases.
 *
 * APDU protocol:
 *   P1=0x00: INIT
 *   P1=0x01: FEED_HM
 *   P1=0x02 P2=0x80: COMPUTE_TARGET
 *   P1=0x03: FEED_TREE_STREAM (encrypted+MAC'd, streaming DFS levels 1-10)
 *   P1=0x04 P2=0/1: FEED_SWAP (L0 authenticated, parent_t1/z0+z1 plaintext)
 *   P1=0x05 P2=idx: GET_SWAP (export z1_merged or z0)
 *   P1=0x90 P2=idx: GET_SIG
 *
 * v0.4.0 — L0 AUTHENTICATION (closes the last plaintext hole in sealed
 *   storage). L0 is now part of the per-key authenticated blob and is
 *   fed via FEED_SWAP as [ct: 8192 B] [tag: 16 B] in both L0_WAIT_L0
 *   and L0_WAIT_L0_AR phases. Tag is computed at CUMULATIVE OFFSET 0
 *   (L0 sits at the front of the blob), and the tree subtree stream
 *   is shifted accordingly: right subtree base offset = 8192, left
 *   subtree base offset = 8192 + 40960 = 49152.
 *
 *   Wire-level cumulative-offset layout:
 *     0           L0 ciphertext (8192 B)
 *     8192        L0 tag        (16 B, skipped in offset counter)
 *     8192        right subtree records (ct||tag per DFS node)
 *     49152       left  subtree records (ct||tag per DFS node)
 *
 *   parent_t1 / z0+z1 remain plaintext — they are transient per-sign
 *   values, not stored alongside the key, and final norm check catches
 *   any tampering anyway.
 *
 * v0.3.0 — PER-NODE AUTHENTICATION on FEED_TREE_STREAM:
 *   Tag = SHAKE256(mac_key || offset_LE(8) || ct, 16).
 *   mac_key = SHAKE256("falcon-tree-mac" || seed, 32).
 *   Verification before decryption, constant-time compare, aborts on
 *   mismatch with SWO_TREE_MAC_FAIL.
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
#include "zkn_errors.h"
#include "handler_falcon_sign.h"
#include "falcon_inner.h"
#include "cx_outsourced.h"

#define FLOGN     10
#define FN        (1 << FLOGN)     /* 1024 */
#define HN        (FN >> 1)        /* 512 */
#define DFS_LOGN  9                /* levels 1-10 = Falcon-512 DFS */
#define NODE_MAC_LEN 16            /* per-node authentication tag length */

/* Dedicated SW for MAC failure, so the host can distinguish it from a
 * generic protocol error. Falls back to SWO_INCORRECT_DATA if the ZKN
 * status word table doesn't define it yet. */
#ifndef SWO_TREE_MAC_FAIL
#define SWO_TREE_MAC_FAIL SWO_INCORRECT_DATA
#endif

/* Tree encryption functions defined after sctx macro (they use _crypto_xof) */

/* ================================================================
 * Level 0 sub-phases
 * ================================================================ */
enum {
    L0_WAIT_L0 = 0,      /* waiting for L0 → enter */
    L0_RIGHT_DFS,         /* right subtree DFS */
    L0_EXPORT_Z1,         /* export z1_merged */
    L0_WAIT_T1,           /* waiting for parent_t1 */
    L0_WAIT_L0_AR,        /* waiting for L0 → after_right */
    L0_LEFT_DFS,          /* left subtree DFS */
    L0_EXPORT_Z0,         /* export z0 */
    L0_WAIT_Z0Z1_S1,      /* z0+z1 → compute s1, write sig */
    L0_WAIT_Z0Z1_S0,      /* z0+z1 → compute s0, norm check */
    L0_SIG_READY           /* done */
};

/* ================================================================
 * Sign context
 * ================================================================ */
typedef struct {
    int phase;
    int l0_phase;
    int depth, done;
    int child_phase[DFS_LOGN];
    fpr stk[6 * HN];          /* 24 KB: DFS stack / level-0 workspace */
    fpr ws[HN];                /* 4 KB: DFS workspace */
    union {
        uint16_t hm[FN];
        int16_t  sig[FN];
    } hm_sig;
    size_t accum_offset;
    sampler_context sc;
    int sig_valid;
    uint32_t sqn_saved;           /* s0 norm partial, checked after s1 */
    cx_outsourced_t outsourced;    /* v0.7.0: tree+mac keys, populated at COMPUTE_TARGET */
    uint8_t tag_buf[NODE_MAC_LEN]; /* v0.3.0: incoming tag during stream */
    size_t tree_byte_offset;
    inner_shake256_context _crypto_xof;  /* v0.7.0: used by hash_to_point only (tree crypto moved to cx_outsourced) */
    /* v0.7.0: device-side hash_to_point inputs */
    uint8_t nonce[40];             /* salt for hash_to_point */
    uint8_t msg[32];               /* fixed 32-B message digest (e.g. keccak256) */
    uint8_t nonce_set;             /* 1 once nonce has been provided/generated */
    uint8_t msg_set;               /* 1 once msg has been provided */
    uint8_t hm_done;               /* 1 once hash_to_point has been computed */
} falcon1024_sign_ctx_t;

#define sctx (*(falcon1024_sign_ctx_t *)(void *)g_zknox._falcon_sign_area)
#define _crypto_xof (sctx._crypto_xof)

/* ================================================================
 * Tree encryption / authentication
 *
 * v0.7.0: outsourced to the cx_outsourced module (cx_outsourced.[ch]).
 * Sign uses cx_outsourced_init at COMPUTE_TARGET (P1=0x02), then
 * cx_outsourced_read_split for each tree node received from the host.
 * The sign handler never writes — only keygen_expand emits records.
 * ================================================================ */

/* ================================================================
 * DFS stack helpers (levels 1-10 = Falcon-512, logn=9, polys ≤512)
 * ================================================================ */
static size_t foff(int d) { return 6 * (HN - (HN >> d)); }
static size_t psz(int d)  { return HN >> d; }
#define STK_LL(s,d)  ((s) + foff(d))
#define STK_T0(s,d)  ((s) + foff(d) + psz(d))
#define STK_T1(s,d)  ((s) + foff(d) + 2 * psz(d))

/* ================================================================
 * Standard DFS (identical to Falcon-512)
 * ================================================================ */
static void dfs_enter(int dep) {
    unsigned ln = DFS_LOGN - dep;
    Zf(poly_split_fft)(STK_T0(sctx.stk, dep+1), STK_T1(sctx.stk, dep+1),
                       STK_T1(sctx.stk, dep), ln);
    sctx.child_phase[dep] = 0;
}
static void dfs_after_right(int dep) {
    size_t m = psz(dep); unsigned ln = DFS_LOGN - dep;
    fpr *pL=STK_LL(sctx.stk,dep),*pt0=STK_T0(sctx.stk,dep),*pt1=STK_T1(sctx.stk,dep);
    fpr *c0=STK_T0(sctx.stk,dep+1),*c1=STK_T1(sctx.stk,dep+1);
    memcpy(sctx.ws,pt1,m*sizeof(fpr));
    Zf(poly_merge_fft)(pt1,c0,c1,ln);
    Zf(poly_sub)(sctx.ws,pt1,ln);
    Zf(poly_mul_fft)(sctx.ws,pL,ln);
    Zf(poly_add)(sctx.ws,pt0,ln);
    Zf(poly_split_fft)(STK_T0(sctx.stk,dep+1),STK_T1(sctx.stk,dep+1),sctx.ws,ln);
    sctx.child_phase[dep] = 1;
}
static void dfs_after_left(int dep) {
    unsigned ln = DFS_LOGN - dep;
    Zf(poly_merge_fft)(sctx.ws,STK_T0(sctx.stk,dep+1),STK_T1(sctx.stk,dep+1),ln);
    if (dep == 0) { /* z_half in ws, z1_half in STK_T1(0) */ }
    else memcpy(STK_T0(sctx.stk,dep),sctx.ws,psz(dep)*sizeof(fpr));
}
static int dfs_feed(const fpr *data) {
    int dep = sctx.depth;
    if (dep >= DFS_LOGN) {
        fpr *pt0=STK_T0(sctx.stk,dep),*pt1=STK_T1(sctx.stk,dep);
        pt0[0]=fpr_of(Zf(sampler)(&sctx.sc,pt0[0],data[0]));
        pt1[0]=fpr_of(Zf(sampler)(&sctx.sc,pt1[0],data[0]));
        for(;;){
            if(dep==0){sctx.done=1;return 1;} dep--;
            if(sctx.child_phase[dep]==0){dfs_after_right(dep);sctx.depth=dep+1;return 0;}
            else dfs_after_left(dep);
        }
    } else {
        memcpy(STK_LL(sctx.stk,dep),data,psz(dep)*sizeof(fpr));
        dfs_enter(dep); sctx.depth=dep+1; return 0;
    }
}

/* ================================================================
 * Level 0 operations
 * ================================================================ */

/* ENTER: split parent_t1 → child t0/t1 for DFS
 * Before: stk[0..1023]=t0, stk[1024..2047]=t1, stk[2048..3071]=L0
 * After:  STK_T0(0)=child_t0[512], STK_T1(0)=child_t1[512] */
static void do_level0_enter(void) {
    /* Copy t1 to non-overlapping area for split source */
    memcpy(sctx.stk + 2*FN, sctx.stk + FN, FN * sizeof(fpr)); /* t1 → [2048..3071] */
    Zf(poly_split_fft)(STK_T0(sctx.stk, 0), STK_T1(sctx.stk, 0),
                       sctx.stk + 2*FN, FLOGN);
    sctx.depth = 0; sctx.done = 0;
    memset(sctx.child_phase, 0, sizeof sctx.child_phase);
}

/* MERGE_RIGHT: merge right subtree result → z1_merged[1024] at stk[0..1023] */
static void do_merge_right(void) {
    fpr *z0_right = sctx.ws;                /* [0..511] */
    fpr *z1_right = STK_T1(sctx.stk, 0);   /* stk[1024..1535] */
    Zf(poly_merge_fft)(sctx.stk, z0_right, z1_right, FLOGN);
    /* z1_merged at stk[0..1023] */
}

/* AFTER_RIGHT: diff = t1-z1, diff*=L, recalc t0, tb0, split for left
 * Before: stk[0..1023]=z1_merged, stk[1024..2047]=parent_t1 (from host),
 *         need L0 in stk[0..1023] after step 4
 * This is called AFTER t1 and L0 have been received. Layout:
 *   stk[1024..2047] = parent_t1 (received)
 *   stk[0..1023] = L0 (received, overwriting z1_merged which host saved)
 */
static void do_after_right(void) {
    fpr *L0   = sctx.stk;          /* [0..1023] */
    fpr *diff = sctx.stk + FN;     /* [1024..2047] = was parent_t1 */
    fpr *buf  = sctx.stk + 2*FN;   /* [2048..3071] */
    fpr ni = fpr_inverse_of_q;

    /* diff = parent_t1 - z1_merged. But z1_merged was at stk[0..1023],
     * now overwritten by L0. We need z1_merged from ws? No.
     * 
     * REORDER: host sends t1 first → stk[1024..2047].
     * Then: diff = t1 - z1_merged (still at stk[0..1023])
     * THEN: host sends L0 → stk[0..1023] (overwrites z1_merged).
     * So this function is called after BOTH t1 and L0 are received.
     * But z1_merged was overwritten by L0...
     *
     * Fix: compute diff BEFORE receiving L0.
     * The handler does diff when t1 arrives, then receives L0.
     * This function is called after L0 arrives, with diff already computed.
     */

    /* At this point: diff at stk[1024..2047] (computed when t1 arrived)
     *                L0 at stk[0..1023] (just received) */

    /* diff *= L0 */
    Zf(poly_mul_fft)(diff, L0, FLOGN);

    /* Recalculate t0 = FFT(hm) * FFT(-F) * (1/q) → stk[0..1023] */
    fpr *t0_recalc = L0; /* reuse stk[0..1023], L0 consumed by mul above? No! 
                            poly_mul_fft(diff, L0) reads L0, writes diff. L0 unchanged.
                            Actually poly_mul_fft(a,b) does a[i] = a[i]*b[i]. L0 unchanged. */
    /* L0 still valid but we're about to overwrite its area with t0_recalc */
    for (size_t u = 0; u < FN; u++) t0_recalc[u] = fpr_of(sctx.hm_sig.hm[u]);
    Zf(FFT)(t0_recalc, FLOGN);
    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_F[u]);
    Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
    Zf(poly_mul_fft)(t0_recalc, buf, FLOGN);
    Zf(poly_mulconst)(t0_recalc, ni, FLOGN);

    /* tb0 = t0 + diff */
    Zf(poly_add)(t0_recalc, diff, FLOGN);

    /* Split tb0 → left child t0/t1 */
    memcpy(sctx.stk + 2*FN, t0_recalc, FN * sizeof(fpr));
    Zf(poly_split_fft)(STK_T0(sctx.stk, 0), STK_T1(sctx.stk, 0),
                       sctx.stk + 2*FN, FLOGN);

    sctx.depth = 0; sctx.done = 0;
    memset(sctx.child_phase, 0, sizeof sctx.child_phase);
}

/* MERGE_LEFT: merge left result → z0[1024] at stk[0..1023] */
static void do_merge_left(void) {
    fpr *z0_left = sctx.ws;
    fpr *z1_left = STK_T1(sctx.stk, 0);
    Zf(poly_merge_fft)(sctx.stk, z0_left, z1_left, FLOGN);
}

/* COMPUTE_S1: z0 at stk[0..1023], z1 at stk[1024..2047]
 * s1 = z0*FFT(-f) + z1*FFT(-F). iFFT. Write sig. Final norm check. */
static int do_compute_s1_and_check(void) {
    fpr *z0 = sctx.stk;
    fpr *z1 = sctx.stk + FN;
    fpr *buf = sctx.stk + 2*FN;

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_f[u]);
    Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
    Zf(poly_mul_fft)(z0, buf, FLOGN);

    for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_F[u]);
    Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
    Zf(poly_mul_fft)(z1, buf, FLOGN);

    Zf(poly_add)(z0, z1, FLOGN);
    Zf(iFFT)(z0, FLOGN);

    for (size_t u = 0; u < FN; u++)
        sctx.hm_sig.sig[u] = (int16_t)-fpr_rint(z0[u]);

    /* Final norm check with sqn from s0 pass */
    return Zf(is_short_half)(sctx.sqn_saved, sctx.hm_sig.sig, FLOGN);
}

/* COMPUTE_S0: z0 at stk[0..1023], z1 at stk[1024..2047]
 * s0 = z0*FFT(g) + z1*FFT(G). iFFT. Compute sqn (save for later).
 * Does NOT call is_short_half — sig not written yet. */
static void do_compute_s0_sqn(void) {
    fpr *z0 = sctx.stk;
    fpr *z1 = sctx.stk + FN;
    fpr *buf = sctx.stk + 2*FN;

    /* Recompute G from (f, g, F). G is not stored persistently in g_zknox
     * (saves 1024 B BSS). complete_private needs 2*FN*sizeof(uint16_t) =
     * 4 KB of tmp; sctx.ws is exactly that size. */
    int8_t G_local[FN];
    Zf(complete_private)(G_local,
                         g_zknox.falcon_f, g_zknox.falcon_g,
                         g_zknox.falcon_F, FLOGN, (uint8_t *)sctx.ws);

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
        int32_t z = (int32_t)sctx.hm_sig.hm[u] - (int32_t)fpr_rint(z0[u]);
        sqn += (uint32_t)(z * z); ng |= sqn;
    }
    sqn |= -(ng >> 31);
    sctx.sqn_saved = sqn;
}

/* ================================================================
 * Where to accumulate swap data based on l0_phase
 * ================================================================ */
static uint8_t *swap_target(void) {
    switch (sctx.l0_phase) {
    case L0_WAIT_L0:       return (uint8_t *)(sctx.stk + 2*FN); /* [2048..3071] */
    case L0_WAIT_T1:       return (uint8_t *)(sctx.stk + FN);   /* [1024..2047] */
    case L0_WAIT_L0_AR:    return (uint8_t *)sctx.stk;           /* [0..1023] */
    case L0_WAIT_Z0Z1_S1:
    case L0_WAIT_Z0Z1_S0:  return (uint8_t *)sctx.stk;           /* [0..2047] */
    default:               return NULL;
    }
}

/* ================================================================
 * APDU handler
 * ================================================================ */
int handler_falcon_sign(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    ZKN_ERROR_INIT();

    switch (p1) {

    case 0x00: /* INIT */
        memset(&sctx, 0, sizeof(falcon1024_sign_ctx_t));
        io_send_sw(SWO_SUCCESS); break;

    case 0x01: /* (was FEED_HM in v0.6.x) — removed in v0.7.0.
                * Host-supplied hm is no longer accepted; the device
                * computes hm via P1=0x07 COMPUTE_HM after FEED_NONCE
                * and FEED_MSG. Hard-reject. */
        return io_send_sw(SWO_INVALID_INS);

    case 0x06: { /* FEED_MSG  — 32-byte message digest (one APDU). */
        if (p1 != 0x06 || p2 != 0x00) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (sctx.msg_set) return io_send_sw(SWO_INCORRECT_DATA);  /* one-shot */
        if (cdata->size != 32) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(sctx.msg, cdata->ptr, 32);
        sctx.msg_set = 1;
        io_send_sw(SWO_SUCCESS); break;
    }

    case 0x07: { /* COMPUTE_HM — hash_to_point(nonce || msg) → sctx.hm_sig.hm */
        if (p2 != 0x80) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (!sctx.nonce_set || !sctx.msg_set)
            return io_send_sw(SWO_INCORRECT_DATA);
        Zf(i_shake256_init)(&_crypto_xof);
        Zf(i_shake256_inject)(&_crypto_xof, sctx.nonce, sizeof sctx.nonce);
        Zf(i_shake256_inject)(&_crypto_xof, sctx.msg,   sizeof sctx.msg);
        Zf(i_shake256_flip)(&_crypto_xof);
        Zf(hash_to_point_vartime)(&_crypto_xof, sctx.hm_sig.hm, FLOGN);
        sctx.hm_done = 1;
        io_send_sw(SWO_SUCCESS); break;
    }

    case 0x08: { /* FEED_NONCE_HOST — host supplies the 40-B nonce (test mode). */
        if (p1 != 0x08 || p2 != 0x00) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (sctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 40) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(sctx.nonce, cdata->ptr, 40);
        sctx.nonce_set = 1;
        io_send_sw(SWO_SUCCESS); break;
    }

    case 0x09: { /* GEN_NONCE_DEVICE — device tirage TRNG (production mode). */
        if (p2 != 0x00) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (sctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        cx_rng_no_throw(sctx.nonce, 40);
        sctx.nonce_set = 1;
        io_send_sw(SWO_SUCCESS); break;
    }

    case 0x91: { /* GET_NONCE — return the 40-B nonce used for this sign. */
        if (p2 != 0x00) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (!sctx.nonce_set) return io_send_sw(SWO_INCORRECT_DATA);
        io_send_response_pointer(sctx.nonce, 40, SWO_SUCCESS); break;
    }

    case 0x02: { /* COMPUTE_TARGET */
        if (p2 != 0x80) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (!sctx.hm_done) return io_send_sw(SWO_INCORRECT_DATA);
        fpr *t0 = sctx.stk;
        fpr *t1 = sctx.stk + FN;
        fpr *buf = sctx.stk + 2*FN;
        fpr ni = fpr_inverse_of_q;
        size_t u;

        for (u = 0; u < FN; u++) t0[u] = fpr_of(sctx.hm_sig.hm[u]);
        Zf(FFT)(t0, FLOGN); memcpy(t1, t0, FN * sizeof(fpr));

        for (u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_f[u]);
        Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
        Zf(poly_mul_fft)(t1, buf, FLOGN);
        Zf(poly_mulconst)(t1, fpr_neg(ni), FLOGN);

        for (u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_F[u]);
        Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
        Zf(poly_mul_fft)(t0, buf, FLOGN);
        Zf(poly_mulconst)(t0, ni, FLOGN);

        inner_shake256_context srng;
        Zf(i_shake256_init)(&srng);
        Zf(i_shake256_inject)(&srng, g_zknox.falcon_seed, 32);
        Zf(i_shake256_inject)(&srng, (uint8_t *)sctx.hm_sig.hm, sizeof sctx.hm_sig.hm);
        Zf(i_shake256_flip)(&srng);
        sctx.sc.sigma_min = fpr_sigma_min_10;
        Zf(prng_init)(&sctx.sc.p, &srng);

        cx_outsourced_init(&sctx.outsourced, g_zknox.falcon_seed, 32);
        sctx.tree_byte_offset = 0;
        sctx.phase = 2;
        sctx.l0_phase = L0_WAIT_L0;
        sctx.accum_offset = 0;
        io_send_sw(SWO_SUCCESS); break;
    }

    case 0x03: { /* FEED_TREE_STREAM (encrypted + per-node MAC, DFS levels 1-10)
                  *
                  * STREAMING PROTOCOL (v0.3.0 wire format):
                  *   Host sends each DFS node as [ciphertext: nb bytes] [tag: 16 B].
                  *   Record size for the current DFS state is determined entirely
                  *   by sctx.depth, so no per-node APDU marker is needed and the
                  *   host may chunk arbitrarily. P2 is ignored.
                  *
                  *   Device behaviour for each full record:
                  *     1. Recompute tag = SHAKE256(mac_key || off_LE || ct, 16).
                  *     2. Constant-time compare vs received tag.
                  *     3. On mismatch: abort with SWO_TREE_MAC_FAIL, DO NOT
                  *        decrypt and DO NOT feed the DFS. (Fault-resistance
                  *        guarantee: no corrupted L-poly value ever enters
                  *        poly_mul_fft / sampler.)
                  *     4. On match: XOR-decrypt in place, advance offset,
                  *        dfs_feed the node.
                  *
                  * Responses:
                  *   - SW=9000, no data  → send more bytes
                  *   - SW=9000, 1 byte 0x01 → subtree DFS complete
                  *   - SW=SWO_TREE_MAC_FAIL → authentication failure on the
                  *     node currently being verified (sctx.tree_byte_offset
                  *     still points to that node; sign is aborted)
                  *
                  * Buffer sizing: sctx.ws is HN fpr = 4 KB, which is exactly
                  * the max ciphertext node size (L poly at DFS depth 0 of
                  * DFS-9). The 16 B tag goes into sctx.tag_buf — not sctx.ws
                  * — so there is no buffer contention even at the worst case.
                  */
        (void)p2;
        if (sctx.l0_phase != L0_RIGHT_DFS && sctx.l0_phase != L0_LEFT_DFS)
            return io_send_sw(SWO_INCORRECT_DATA);

        const uint8_t *src = cdata->ptr;
        size_t remaining   = cdata->size;

        while (remaining > 0) {
            int dep = sctx.depth;
            size_t node_bytes = (dep >= DFS_LOGN)
                                ? sizeof(fpr)
                                : psz(dep) * sizeof(fpr);
            size_t full_record = node_bytes + NODE_MAC_LEN;

            /* Safety: ciphertext must fit the accumulation buffer. Tag lives
             * in sctx.tag_buf (separate 16 B scratch), so we only compare
             * node_bytes against sizeof(sctx.ws), not full_record. */
            if (node_bytes > sizeof(sctx.ws))
                return io_send_sw(SWO_INCORRECT_DATA);

            /* Route incoming bytes: first node_bytes go to sctx.ws (ct),
             * next NODE_MAC_LEN go to sctx.tag_buf. At most one region is
             * filled per loop iteration so the logic stays simple. */
            size_t take;
            if (sctx.accum_offset < node_bytes) {
                size_t need = node_bytes - sctx.accum_offset;
                take = remaining < need ? remaining : need;
                memcpy(((uint8_t *)sctx.ws) + sctx.accum_offset, src, take);
            } else {
                size_t tag_off = sctx.accum_offset - node_bytes;
                size_t need    = NODE_MAC_LEN - tag_off;
                take = remaining < need ? remaining : need;
                memcpy(sctx.tag_buf + tag_off, src, take);
            }
            sctx.accum_offset += take;
            src               += take;
            remaining         -= take;

            if (sctx.accum_offset == full_record) {
                /* Full record: verify-then-decrypt via cx_outsourced. */
                if (cx_outsourced_read_split(&sctx.outsourced,
                                             sctx.tree_byte_offset,
                                             (uint8_t *)sctx.ws, node_bytes,
                                             sctx.tag_buf) != CXO_OK)
                    return io_send_sw(SWO_TREE_MAC_FAIL);
                sctx.tree_byte_offset += node_bytes;

                int rc = dfs_feed((const fpr *)sctx.ws);
                sctx.accum_offset = 0;

                if (rc == 1) {
                    /* Subtree complete. No bytes may remain in this APDU. */
                    if (remaining > 0)
                        return io_send_sw(SWO_INCORRECT_DATA);
                    if (sctx.l0_phase == L0_RIGHT_DFS) {
                        do_merge_right();
                        sctx.l0_phase = L0_EXPORT_Z1;
                    } else {
                        do_merge_left();
                        sctx.l0_phase = L0_EXPORT_Z0;
                    }
                    uint8_t flag = 1;
                    io_send_response_pointer(&flag, 1, SWO_SUCCESS);
                    return 0;
                }
            }
        }
        io_send_sw(SWO_SUCCESS);
        break;
    }

    case 0x04: { /* FEED_SWAP
                  *
                  * v0.4.0 routing:
                  *   L0_WAIT_L0   — expects [L0_ct: 8192 B] [L0_tag: 16 B], tag@off=0
                  *   L0_WAIT_L0_AR — same (second L0 feed, before after_right)
                  *   L0_WAIT_T1   — plaintext parent_t1 (8192 B)
                  *   L0_WAIT_Z0Z1_S0 / _S1 — plaintext z0+z1 (16384 B)
                  *
                  * For authenticated phases, ciphertext fills the target slot
                  * in sctx.stk (first 8192 B); the trailing 16 B tag fills
                  * sctx.tag_buf. On P2=0x01 we verify tag at cumulative-offset
                  * 0 (L0 is always the first record in the authenticated blob),
                  * decrypt in place, then jump tree_byte_offset past L0 so the
                  * subsequent FEED_TREE_STREAM sees the right base (8192 for
                  * right subtree, 49152 for left).
                  */
        uint8_t *tgt = swap_target();
        if (!tgt) return io_send_sw(SWO_INCORRECT_DATA);

        int auth = (sctx.l0_phase == L0_WAIT_L0
                 || sctx.l0_phase == L0_WAIT_L0_AR);

        if (auth) {
            /* Two-region accumulator: ciphertext into tgt[0..8191],
             * then tag into sctx.tag_buf[0..15]. */
            const size_t ct_bytes = FN * sizeof(fpr); /* 8192 */
            const uint8_t *src = cdata->ptr;
            size_t remaining   = cdata->size;

            while (remaining > 0) {
                size_t take;
                if (sctx.accum_offset < ct_bytes) {
                    size_t need = ct_bytes - sctx.accum_offset;
                    take = remaining < need ? remaining : need;
                    memcpy(tgt + sctx.accum_offset, src, take);
                } else {
                    size_t tag_off = sctx.accum_offset - ct_bytes;
                    if (tag_off >= NODE_MAC_LEN)
                        return io_send_sw(SWO_INCORRECT_DATA); /* overrun */
                    size_t need = NODE_MAC_LEN - tag_off;
                    take = remaining < need ? remaining : need;
                    memcpy(sctx.tag_buf + tag_off, src, take);
                }
                sctx.accum_offset += take;
                src               += take;
                remaining         -= take;
            }

            if (p2 == 0x00) {
                io_send_sw(SWO_SUCCESS);
                break;
            }
            /* P2 == 0x01: final chunk. Must have exactly ct + tag bytes. */
            if (sctx.accum_offset != ct_bytes + NODE_MAC_LEN)
                return io_send_sw(SWO_INCORRECT_DATA);

            /* Verify-then-decrypt L0 at cumulative-offset 0 via cx_outsourced. */
            if (cx_outsourced_read_split(&sctx.outsourced, 0,
                                         tgt, ct_bytes, sctx.tag_buf) != CXO_OK)
                return io_send_sw(SWO_TREE_MAC_FAIL);

            /* Phase transition, mirrored from v0.3.0 L0 handling. */
            sctx.accum_offset = 0;
            if (sctx.l0_phase == L0_WAIT_L0) {
                /* First L0 — enter level 0; next stream feed is RIGHT
                 * subtree at cumulative byte offset ct_bytes. */
                do_level0_enter();
                sctx.tree_byte_offset = ct_bytes;  /* 8192 */
                sctx.l0_phase = L0_RIGHT_DFS;
            } else { /* L0_WAIT_L0_AR */
                /* Second L0 — after_right. tree_byte_offset is already
                 * at right_end (= 49152); leave it for left subtree stream. */
                do_after_right();
                sctx.l0_phase = L0_LEFT_DFS;
            }
            io_send_sw(SWO_SUCCESS);
            break;
        }

        /* ==== Plaintext paths (parent_t1, z0+z1) — unchanged from v0.3.0 ==== */
        if (p2 == 0x00) {
            memcpy(tgt + sctx.accum_offset, cdata->ptr, cdata->size);
            sctx.accum_offset += cdata->size;
            io_send_sw(SWO_SUCCESS);
        } else {
            if (cdata->size > 0) {
                memcpy(tgt + sctx.accum_offset, cdata->ptr, cdata->size);
                sctx.accum_offset += cdata->size;
            }
            sctx.accum_offset = 0;

            switch (sctx.l0_phase) {
            case L0_WAIT_T1:
                /* diff = parent_t1 - z1_merged (z1_merged still at stk[0..1023]) */
                Zf(poly_sub)(sctx.stk + FN, sctx.stk, FLOGN);
                sctx.l0_phase = L0_WAIT_L0_AR;
                io_send_sw(SWO_SUCCESS);
                break;

            case L0_WAIT_Z0Z1_S0:
                do_compute_s0_sqn();
                sctx.l0_phase = L0_WAIT_Z0Z1_S1;
                io_send_sw(SWO_SUCCESS);
                break;

            case L0_WAIT_Z0Z1_S1: {
                int ok = do_compute_s1_and_check();
                sctx.sig_valid = ok;
                sctx.l0_phase = L0_SIG_READY;
                uint8_t r = ok ? 1 : 0;
                io_send_response_pointer(&r, 1, SWO_SUCCESS);
                break;
            }

            default:
                return io_send_sw(SWO_INCORRECT_DATA);
            }
        }
        break;
    }

    case 0x05: { /* GET_SWAP (export z1_merged or z0) */
        if (sctx.l0_phase != L0_EXPORT_Z1 && sctx.l0_phase != L0_EXPORT_Z0)
            return io_send_sw(SWO_INCORRECT_DATA);
        size_t total = FN * sizeof(fpr); /* 8192 */
        size_t off = (size_t)p2 * 255;
        if (off >= total) {
            /* All exported → transition.
             *
             * v0.6.0 FIX: skip the L0_WAIT_T1 phase entirely. Previously the
             * host had to feed parent_t1 back, but the host doesn't have it
             * (it depends on private key f, which never leaves the device).
             * Instead we recompute t1 = -FFT(hm)*FFT(-f)*(1/q) on-device,
             * then compute diff = t1 - z1_merged in place. This is the
             * same formula used in COMPUTE_TARGET. The host now goes
             * straight from GET_SWAP(z1) to FEED_SWAP(L0_after_right).
             */
            if (sctx.l0_phase == L0_EXPORT_Z1) {
                /* z1_merged is at stk[0..FN-1]. Compute t1 into stk[FN..2*FN]. */
                fpr *t1  = sctx.stk + FN;
                fpr *buf = sctx.stk + 2*FN;
                fpr ni   = fpr_inverse_of_q;
                for (size_t u = 0; u < FN; u++) t1[u] = fpr_of(sctx.hm_sig.hm[u]);
                Zf(FFT)(t1, FLOGN);
                for (size_t u = 0; u < FN; u++) buf[u] = fpr_of(g_zknox.falcon_f[u]);
                Zf(FFT)(buf, FLOGN); Zf(poly_neg)(buf, FLOGN);
                Zf(poly_mul_fft)(t1, buf, FLOGN);
                Zf(poly_mulconst)(t1, fpr_neg(ni), FLOGN);
                /* diff = t1 - z1_merged */
                Zf(poly_sub)(t1, sctx.stk, FLOGN);
                /* stk[FN..2*FN] now holds diff, ready for do_after_right. */
                sctx.l0_phase = L0_WAIT_L0_AR;
            } else {
                sctx.l0_phase = L0_WAIT_Z0Z1_S0;  /* s0 first (reads hm) */
            }
            sctx.accum_offset = 0;
            io_send_sw(SWO_SUCCESS);
        } else {
            size_t chunk = total - off; if (chunk > 255) chunk = 255;
            io_send_response_pointer(((uint8_t *)sctx.stk) + off, chunk, SWO_SUCCESS);
        }
        break;
    }

    case 0x90: { /* GET_SIG */
        if (!sctx.sig_valid) return io_send_sw(SWO_INCORRECT_DATA);
        size_t total = FN * sizeof(int16_t);
        size_t off = (size_t)p2 * 255;
        if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
        size_t chunk = total - off; if (chunk > 255) chunk = 255;
        io_send_response_pointer(((uint8_t *)sctx.hm_sig.sig) + off, chunk, SWO_SUCCESS);
        break;
    }

    default:
        return io_send_sw(SWO_INCORRECT_P1_P2);
    }
    ZKN_ERROR_CLOSE_SEND();
}

void *falcon_sign_get_tmp_buffer(size_t *out_size) {
    /* Full sign area for Falcon-1024 keygen (needs 28672 bytes).
     * sctx.stk alone is only 24576 — not enough. */
    *out_size = FALCON_SIGN_BSS_SIZE;
    return (void *)g_zknox._falcon_sign_area;
}
