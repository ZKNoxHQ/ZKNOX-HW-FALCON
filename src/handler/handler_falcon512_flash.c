/*
 * handler_falcon512_flash.c — Falcon-512 flash variant — phase 2b
 *
 * KEYGEN, GET_PK, KEYGEN_EXPAND, DUMP_NVM — unchanged from phase 2a.
 * SIGN and GET_SIG moved to handler_falcon512_flash_sign.c (real impl).
 *
 * Walker structure for KEYGEN_EXPAND duplicated verbatim from
 * handler_falcon512_keygen_expand.c (streaming variant) with one
 * substitution: emit_node_into() → flash_emit_node_into() (nvm_write
 * plaintext at cum_off, no encryption / no MAC since NVRAM is in the
 * same TCB as the seed).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../sw.h"
#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "../globals.h"
#include "send_response.h"

#include "handler_falcon512_flash.h"
#include "handler_falcon_sign.h"   /* declares falcon_sign_get_tmp_buffer */
#include "falcon_inner.h"

/* ===================================================================== *
 * Falcon-512 dimensions and DFS walker geometry
 * ===================================================================== */
#define FLOGN        9
#define FN           (1 << FLOGN)            /* 512 */
#define HN           (FN >> 1)
#define DFS_LOGN     8
#define SLOT_BYTES   (FN * sizeof(fpr))      /* 4096 */
#define N_SLOTS      4

#define FALCON_H_OFFSET (FALCON_SIGN_BSS_SIZE - FN * (int)sizeof(uint16_t))
#define FALCON_H_PTR    ((uint16_t *)((uint8_t *)g_zknox._falcon_sign_area + FALCON_H_OFFSET))

#define FALCON512_G_TEMP_OFFSET 14336
#define FALCON512_G_TEMP_PTR    ((int8_t *)((uint8_t *)g_zknox._falcon_sign_area + FALCON512_G_TEMP_OFFSET))

#define WORK_BUF ((uint8_t *)g_zknox._falcon_sign_area)
#define SLOT(i)  ((fpr *)(WORK_BUF + (size_t)(i) * SLOT_BYTES))

_Static_assert(N_SLOTS * SLOT_BYTES <= FALCON_SIGN_BSS_SIZE,
               "work_buf exceeds _falcon_sign_area");

extern cx_err_t falcon512_derive_seed(uint8_t falcon_seed[32]);

/* ===================================================================== *
 * NVRAM storage
 * ===================================================================== */
const uint8_t N_falcon_tree_512_storage[FALCON_TREE_NVM_SIZE_512] = {0};
const uint8_t N_falcon_pk_512_storage[FALCON_PK_NVM_SIZE_512] = {0};
const uint8_t N_falcon_tree_512_ready_storage = 0;

#define N_falcon_tree_512       ((const uint8_t *)PIC(N_falcon_tree_512_storage))
#define N_falcon_pk_512         ((const uint8_t *)PIC(N_falcon_pk_512_storage))
#define N_falcon_tree_512_ready (*(const uint8_t *)PIC(&N_falcon_tree_512_ready_storage))

/* ===================================================================== *
 * Walker state — LOCAL to keygen_expand path
 * ===================================================================== */
enum {
    KE_IDLE = 0,
    KE_WALK_RIGHT,
    KE_WALK_LEFT,
    KE_DONE
};

typedef struct {
    int     phase;
    int     depth;
    int     child_phase[DFS_LOGN + 1];
    size_t  ptr_offset[DFS_LOGN + 2];
    size_t  cum_off;
} falcon_flash_state_t;

static falcon_flash_state_t g_flash_state;
#define kctx g_flash_state

/* ===================================================================== *
 * Flash emit: write plaintext node to NVRAM at cum_off
 * ===================================================================== */
static void flash_emit_node_into(uint8_t *src, size_t nb) {
    nvm_write((void *)(N_falcon_tree_512 + kctx.cum_off), src, (unsigned int)nb);
    kctx.cum_off += nb;
}

/* ===================================================================== *
 * Keygen-expand helpers (verbatim from streaming variant)
 * ===================================================================== */
static void rematerialize(fpr *dst, const int8_t *src, int do_neg) {
    for (size_t u = 0; u < FN; u++) dst[u] = fpr_of(src[u]);
    Zf(FFT)(dst, FLOGN);
    if (do_neg) Zf(poly_neg)(dst, FLOGN);
}

static void gram_phase(const int8_t *G_buf) {
    fpr *G00 = SLOT(0);
    fpr *G01 = SLOT(1);
    fpr *G11 = SLOT(2);
    fpr *SCR = SLOT(3);

    rematerialize(G00, g_zknox.falcon_g, 0);
    Zf(poly_mulselfadj_fft)(G00, FLOGN);
    rematerialize(SCR, g_zknox.falcon_f, 1);
    Zf(poly_mulselfadj_fft)(SCR, FLOGN);
    Zf(poly_add)(G00, SCR, FLOGN);

    rematerialize(G01, g_zknox.falcon_g, 0);
    rematerialize(SCR, G_buf, 0);
    Zf(poly_muladj_fft)(G01, SCR, FLOGN);
    rematerialize(G11, g_zknox.falcon_f, 1);
    rematerialize(SCR, g_zknox.falcon_F, 1);
    Zf(poly_muladj_fft)(G11, SCR, FLOGN);
    Zf(poly_add)(G01, G11, FLOGN);

    rematerialize(G11, G_buf, 0);
    Zf(poly_mulselfadj_fft)(G11, FLOGN);
    rematerialize(SCR, g_zknox.falcon_F, 1);
    Zf(poly_mulselfadj_fft)(SCR, FLOGN);
    Zf(poly_add)(G11, SCR, FLOGN);
}

static void ldlmv_fft_inplace(fpr *g00, fpr *g01_l10, fpr *g11_d11) {
    size_t hn = HN;
    for (size_t u = 0; u < hn; u++) {
        fpr g00_re = g00[u],         g00_im = g00[u + hn];
        fpr g01_re = g01_l10[u],     g01_im = g01_l10[u + hn];
        fpr g11_re = g11_d11[u],     g11_im = g11_d11[u + hn];
        fpr m  = fpr_inv(fpr_add(fpr_sqr(g00_re), fpr_sqr(g00_im)));
        fpr br = fpr_mul(g00_re, m);
        fpr bi = fpr_mul(fpr_neg(g00_im), m);
        fpr mu_re = fpr_sub(fpr_mul(g01_re, br), fpr_mul(g01_im, bi));
        fpr mu_im = fpr_add(fpr_mul(g01_re, bi), fpr_mul(g01_im, br));
        fpr xi_re = fpr_sub(fpr_mul(mu_re, g01_re),
                            fpr_mul(mu_im, fpr_neg(g01_im)));
        fpr xi_im = fpr_add(fpr_mul(mu_re, fpr_neg(g01_im)),
                            fpr_mul(mu_im, g01_re));
        g11_d11[u]      = fpr_sub(g11_re, xi_re);
        g11_d11[u + hn] = fpr_sub(g11_im, xi_im);
        g01_l10[u]      = mu_re;
        g01_l10[u + hn] = fpr_neg(mu_im);
    }
}

static void compute_l0_phase(void) {
    kctx.cum_off = 0;
    int8_t G_buf[FN];
    Zf(complete_private)(G_buf, g_zknox.falcon_f, g_zknox.falcon_g,
                         g_zknox.falcon_F, FLOGN, (uint8_t *)SLOT(0));
    gram_phase(G_buf);
    ldlmv_fft_inplace(SLOT(0), SLOT(1), SLOT(2));
    flash_emit_node_into((uint8_t *)SLOT(1), FN * sizeof(fpr));
}

static void prep_right_phase(void) {
    fpr *TMP = SLOT(3);
    Zf(poly_split_fft)(TMP, TMP + HN, SLOT(0), FLOGN);
    Zf(poly_split_fft)(SLOT(0), SLOT(0) + HN, SLOT(2), FLOGN);
    memcpy(SLOT(2), TMP, FN * sizeof(fpr));

    kctx.depth = 0;
    memset(kctx.child_phase, 0, sizeof kctx.child_phase);
    kctx.ptr_offset[0] = 0 * SLOT_BYTES;
}

static void prep_left_phase(void) {
    kctx.depth = 0;
    memset(kctx.child_phase, 0, sizeof kctx.child_phase);
    kctx.ptr_offset[0] = 2 * SLOT_BYTES;
}

static void flash_walker_step(int tree_slot, int tmp_slot, int end_phase) {
    int dep = kctx.depth;
    unsigned logn = DFS_LOGN - (unsigned)dep;
    size_t n = (size_t)1 << logn;
    fpr     *g_buf        = (fpr *)(WORK_BUF + kctx.ptr_offset[dep]);
    uint8_t *tree_stage_b = WORK_BUF + (size_t)tree_slot * SLOT_BYTES;
    fpr     *tree_stage   = (fpr *)tree_stage_b;
    fpr     *tmp_stage    = (fpr *)(WORK_BUF + (size_t)tmp_slot * SLOT_BYTES);

    if (n == 1) {
        tree_stage[0] = fpr_mul(fpr_sqrt(g_buf[0]), fpr_inv_sigma);
        flash_emit_node_into(tree_stage_b, sizeof(fpr));
        for (;;) {
            if (dep == 0) { kctx.phase = end_phase; kctx.depth = 0; return; }
            dep--;
            if (kctx.child_phase[dep] == 0) {
                kctx.child_phase[dep] = 1;
                unsigned pln = DFS_LOGN - (unsigned)dep;
                size_t   pn  = (size_t)1 << pln;
                dep++;
                kctx.ptr_offset[dep] = kctx.ptr_offset[dep - 1] + pn * sizeof(fpr);
                kctx.depth = dep;
                return;
            }
        }
    }

    fpr *g0 = g_buf, *g1 = g_buf + n;
    size_t hn_l = n >> 1;
    Zf(poly_LDLmv_fft)(tmp_stage, tree_stage, g0, g1, g0, logn);
    flash_emit_node_into(tree_stage_b, n * sizeof(fpr));
    Zf(poly_split_fft)(g1, g1 + hn_l, g0, logn);
    Zf(poly_split_fft)(g0, g0 + hn_l, tmp_stage, logn);
    kctx.child_phase[dep] = 0;
    dep++;
    kctx.ptr_offset[dep] = kctx.ptr_offset[dep - 1];
    kctx.depth = dep;
}

/* ===================================================================== *
 * Handlers
 * ===================================================================== */
int handler_falcon512_flash_keygen(buffer_t *cdata) {
    if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);

    cx_err_t derr = falcon512_derive_seed(g_zknox.falcon_seed);
    if (derr != CX_OK) return io_send_sw((uint16_t)derr);

    inner_shake256_context rng;
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, g_zknox.falcon_seed, 32);
    inner_shake256_flip(&rng);

    size_t tmp_size;
    uint8_t *tmp = falcon_sign_get_tmp_buffer(&tmp_size);
    Zf(keygen)(&rng,
               g_zknox.falcon_f, g_zknox.falcon_g,
               g_zknox.falcon_F, FALCON512_G_TEMP_PTR,
               FALCON_H_PTR, FLOGN, tmp);

    nvm_write((void *)N_falcon_pk_512, (uint8_t *)FALCON_H_PTR, FALCON_PK_NVM_SIZE_512);

    uint8_t zero = 0;
    nvm_write((void *)&N_falcon_tree_512_ready, &zero, 1);

    g_zknox.falcon_ready = 1;

    io_send_response_pointer((uint8_t *)N_falcon_pk_512, 255, SWO_SUCCESS);
    return 0;
}


int handler_falcon512_flash_keygen_expand(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    if (p1 != 0 || p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
    if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
    if (!g_zknox.falcon_ready) return io_send_sw(SWO_INCORRECT_DATA);

    compute_l0_phase();

    prep_right_phase();
    kctx.phase = KE_WALK_RIGHT;
    do {
        flash_walker_step(1, 3, KE_WALK_LEFT);
    } while (kctx.phase == KE_WALK_RIGHT);

    prep_left_phase();
    do {
        flash_walker_step(0, 1, KE_DONE);
    } while (kctx.phase == KE_WALK_LEFT);

    uint8_t one = 1;
    nvm_write((void *)&N_falcon_tree_512_ready, &one, 1);

    return io_send_sw(SWO_SUCCESS);
}


int handler_falcon512_flash_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata;
    if (!g_zknox.falcon_ready) return io_send_sw(SWO_INCORRECT_DATA);

    size_t total = FALCON_PK_NVM_SIZE_512;
    size_t off   = (size_t)p1 * 255;
    if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
    size_t chunk = p2 ? p2 : 255;
    if (off + chunk > total) chunk = total - off;
    io_send_response_pointer((uint8_t *)(N_falcon_pk_512 + off), chunk, SWO_SUCCESS);
    return 0;
}


int handler_falcon512_flash_dump_nvm(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata;
    if (N_falcon_tree_512_ready != 1) return io_send_sw(SWO_INCORRECT_DATA);

    size_t chunk_idx = ((size_t)p1 << 8) | (size_t)p2;
    size_t off = chunk_idx * 255;
    if (off >= FALCON_TREE_NVM_SIZE_512) return io_send_sw(SWO_INCORRECT_P1_P2);
    size_t chunk = FALCON_TREE_NVM_SIZE_512 - off;
    if (chunk > 255) chunk = 255;
    io_send_response_pointer((uint8_t *)(N_falcon_tree_512 + off), chunk, SWO_SUCCESS);
    return 0;
}
