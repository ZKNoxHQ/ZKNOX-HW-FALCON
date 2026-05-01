/*
 * wire_sim.c — Software replica of handler_falcon_keygen_expand.c.
 *
 * Compiled against Lin et al's reference Falcon implementation (which is
 * byte-equivalent to the NIST round-3-final reference). Replicates the
 * exact byte-level behavior of the device, parametrized on FALCON_VARIANT
 * (passed via -DFALCON_VARIANT=512 or =1024 at compile time).
 *
 * Inputs:
 *   /tmp/falcon_seed.bin   32-byte SLIP-10 derived seed (the same seed
 *                          that the device gets from falcon_derive_seed)
 * Outputs:
 *   /tmp/falcon_h_raw.bin     uint16_t[FN] LE — pubkey (the 'h' polynomial)
 *   /tmp/falcon_wire.bin      complete wire blob: L0_record || right || left
 *
 * Build:
 *   gcc -O2 -DFALCON_VARIANT=512 -I/path/to/Lin_et_al/PRI \
 *       wire_sim.c sign.c keygen.c codec.c common.c falcon.c fft.c \
 *       fpr.c rng.c shake.c vrfy.c -o wire_sim -lm
 *
 * The simulator runs in user-space, so it uses set_fpu_cw(2) for x86 FP precision
 * (matches Falcon's expected behavior; on Cortex-M33 with FPEMU this is moot).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "inner.h"

#ifndef FALCON_VARIANT
#define FALCON_VARIANT 1024
#endif

#if FALCON_VARIANT == 1024
#define FLOGN          10
#define FN             1024
#elif FALCON_VARIANT == 512
#define FLOGN          9
#define FN             512
#else
#error "FALCON_VARIANT must be 512 or 1024"
#endif

#define HN             (FN >> 1)
#define DFS_LOGN       (FLOGN - 1)
#define NODE_MAC_LEN   16
#define SLOT_BYTES     (FN * sizeof(fpr))    /* one fpr poly */
#define N_SLOTS        4

/* ===================================================================
 * cx_outsourced replica (matches src/handler/cx_outsourced.c byte-for-byte)
 * =================================================================== */

static void off_to_le8(size_t byte_offset, uint8_t off_le[8]) {
    off_le[0] = (uint8_t)(byte_offset);
    off_le[1] = (uint8_t)(byte_offset >> 8);
    off_le[2] = (uint8_t)(byte_offset >> 16);
    off_le[3] = (uint8_t)(byte_offset >> 24);
    off_le[4] = 0; off_le[5] = 0; off_le[6] = 0; off_le[7] = 0;
}

static void apply_keystream(const uint8_t key[32],
                            uint8_t *data, size_t len,
                            size_t byte_offset) {
    uint8_t off_le[8];
    off_to_le8(byte_offset, off_le);
    inner_shake256_context xof;
    inner_shake256_init(&xof);
    inner_shake256_inject(&xof, key, 32);
    inner_shake256_inject(&xof, off_le, 8);
    inner_shake256_flip(&xof);
    uint8_t ks[64];
    size_t pos = 0;
    while (pos < len) {
        size_t c = len - pos;
        if (c > 64) c = 64;
        inner_shake256_extract(&xof, ks, c);
        for (size_t i = 0; i < c; i++) data[pos + i] ^= ks[i];
        pos += c;
    }
}

static void compute_tag(const uint8_t mkey[32],
                        const uint8_t *ciphertext, size_t len,
                        size_t byte_offset,
                        uint8_t tag_out[NODE_MAC_LEN]) {
    uint8_t off_le[8];
    off_to_le8(byte_offset, off_le);
    inner_shake256_context xof;
    inner_shake256_init(&xof);
    inner_shake256_inject(&xof, mkey, 32);
    inner_shake256_inject(&xof, off_le, 8);
    inner_shake256_inject(&xof, ciphertext, len);
    inner_shake256_flip(&xof);
    inner_shake256_extract(&xof, tag_out, NODE_MAC_LEN);
}

static void derive_subkey(uint8_t out[32],
                          const char *label, size_t label_len,
                          const uint8_t *kdf_input, size_t kdf_input_len) {
    inner_shake256_context xof;
    inner_shake256_init(&xof);
    inner_shake256_inject(&xof, (const uint8_t *)label, label_len);
    inner_shake256_inject(&xof, kdf_input, kdf_input_len);
    inner_shake256_flip(&xof);
    inner_shake256_extract(&xof, out, 32);
}

/* ===================================================================
 * Device-side state replica
 * =================================================================== */

static struct {
    uint8_t  tree_key[32];
    uint8_t  mac_key[32];
    size_t   cum_off;
    uint8_t  l0_tag[NODE_MAC_LEN];
    /* Walker state (matches device): */
    int      depth;
    int      child_phase[FLOGN + 1];
    size_t   ptr_offset[FLOGN + 1];
} kctx;

/* Persistent secret material (matches g_zknox) */
static struct {
    uint8_t falcon_seed[32];
    int8_t  falcon_f[FN];
    int8_t  falcon_g[FN];
    int8_t  falcon_F[FN];
    int8_t  falcon_G[FN];
} g_zknox;

/* Work buffer mimicking the device's _falcon_sign_area (4 slots × FN fpr) */
static uint8_t WORK_BUF[N_SLOTS * SLOT_BYTES] __attribute__((aligned(8)));
#define SLOT(i)  ((fpr *)(WORK_BUF + (size_t)(i) * SLOT_BYTES))

/* ===================================================================
 * Phase 0 — Gram + L0 LDL + L0 emit
 * =================================================================== */

static void rematerialize(fpr *dst, const int8_t *src, int do_neg) {
    for (size_t u = 0; u < FN; u++) dst[u] = fpr_of(src[u]);
    Zf(FFT)(dst, FLOGN);
    if (do_neg) Zf(poly_neg)(dst, FLOGN);
}

static void gram_phase(void) {
    fpr *G00 = SLOT(0);
    fpr *G01 = SLOT(1);
    fpr *G11 = SLOT(2);
    fpr *SCR = SLOT(3);

    /* g00 = b00·adj(b00) + b01·adj(b01),  b00 = FFT(g), b01 = -FFT(f) */
    rematerialize(G00, g_zknox.falcon_g, 0);
    Zf(poly_mulselfadj_fft)(G00, FLOGN);
    rematerialize(SCR, g_zknox.falcon_f, 1);
    Zf(poly_mulselfadj_fft)(SCR, FLOGN);
    Zf(poly_add)(G00, SCR, FLOGN);

    /* g01 = b00·adj(b10) + b01·adj(b11),  b10 = FFT(G), b11 = -FFT(F) */
    rematerialize(G01, g_zknox.falcon_g, 0);
    rematerialize(SCR, g_zknox.falcon_G, 0);
    Zf(poly_muladj_fft)(G01, SCR, FLOGN);
    rematerialize(G11, g_zknox.falcon_f, 1);
    rematerialize(SCR, g_zknox.falcon_F, 1);
    Zf(poly_muladj_fft)(G11, SCR, FLOGN);
    Zf(poly_add)(G01, G11, FLOGN);

    /* g11 = b10·adj(b10) + b11·adj(b11) */
    rematerialize(G11, g_zknox.falcon_G, 0);
    Zf(poly_mulselfadj_fft)(G11, FLOGN);
    rematerialize(SCR, g_zknox.falcon_F, 1);
    Zf(poly_mulselfadj_fft)(SCR, FLOGN);
    Zf(poly_add)(G11, SCR, FLOGN);
}

/* In-place LDLmv at top level (matches handler_falcon_keygen_expand.c) */
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
        g01_l10[u + hn] = fpr_neg(mu_im);  /* l10 = conj(mu) */
    }
}

static void emit_node_into(uint8_t *target_buf, size_t nb) {
    apply_keystream(kctx.tree_key, target_buf, nb, kctx.cum_off);
    compute_tag(kctx.mac_key, target_buf, nb, kctx.cum_off,
                target_buf + nb);
    kctx.cum_off += nb;
}

static void compute_l0_phase(uint8_t *out_l0_record) {
    kctx.cum_off = 0;
    derive_subkey(kctx.tree_key, "falcon-tree-key", 15,
                  g_zknox.falcon_seed, 32);
    derive_subkey(kctx.mac_key, "falcon-tree-mac", 15,
                  g_zknox.falcon_seed, 32);

    gram_phase();
    ldlmv_fft_inplace(SLOT(0), SLOT(1), SLOT(2));

    /* Encrypt L0 (SLOT(1)) in place, tag into kctx.l0_tag */
    apply_keystream(kctx.tree_key, (uint8_t *)SLOT(1),
                    FN * sizeof(fpr), kctx.cum_off);
    compute_tag(kctx.mac_key, (uint8_t *)SLOT(1),
                FN * sizeof(fpr), kctx.cum_off, kctx.l0_tag);
    kctx.cum_off += FN * sizeof(fpr);

    /* Build the L0 record: ciphertext (8192/4096 B) || tag (16 B) */
    memcpy(out_l0_record, SLOT(1), FN * sizeof(fpr));
    memcpy(out_l0_record + FN * sizeof(fpr), kctx.l0_tag, NODE_MAC_LEN);
}

/* ===================================================================
 * Phase 1 / 2 — DFS walker
 * =================================================================== */

static void prep_right_phase(void) {
    fpr *TMP = SLOT(3);
    /* TMP ← split(d00) */
    Zf(poly_split_fft)(TMP, TMP + HN, SLOT(0), FLOGN);
    /* SLOT(0) ← split(d11) (in place) — but SLOT(0) was d00, was just splitted into TMP.
     * We need d11 from SLOT(2). */
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

/* Returns 1 if the walker is now done (subtree complete), 0 otherwise.
 * On return, the emitted node is at WORK_BUF + tree_slot*SLOT_BYTES,
 * with length stored via *out_node_len. */
static int walker_step(int tree_slot, int tmp_slot, size_t *out_node_len) {
    int dep = kctx.depth;
    unsigned logn = DFS_LOGN - (unsigned)dep;
    size_t n = (size_t)1 << logn;
    fpr     *g_buf        = (fpr *)(WORK_BUF + kctx.ptr_offset[dep]);
    uint8_t *tree_stage_b = WORK_BUF + (size_t)tree_slot * SLOT_BYTES;
    fpr     *tree_stage   = (fpr *)tree_stage_b;
    fpr     *tmp_stage    = (fpr *)(WORK_BUF + (size_t)tmp_slot * SLOT_BYTES);

    if (n == 1) {
        /* Leaf — emit fpr_sqrt(g_buf[0]) * inv_sigma.
         * The device uses a scalar fpr_inv_sigma (legacy v0.5 / v0.6 value),
         * not the per-logn array used by Lin et al. We replicate that exactly
         * to produce a wire byte-identical to the device. */
        static const fpr USER_FPR_INV_SIGMA = (fpr)4573359825155195350ULL;
        tree_stage[0] = fpr_mul(fpr_sqrt(g_buf[0]), USER_FPR_INV_SIGMA);
        emit_node_into(tree_stage_b, sizeof(fpr));
        *out_node_len = sizeof(fpr) + NODE_MAC_LEN;
        /* Bubble up */
        for (;;) {
            if (dep == 0) {
                kctx.depth = 0;
                return 1;  /* end of subtree */
            }
            dep--;
            if (kctx.child_phase[dep] == 0) {
                kctx.child_phase[dep] = 1;
                unsigned pln = DFS_LOGN - (unsigned)dep;
                size_t   pn  = (size_t)1 << pln;
                dep++;
                kctx.ptr_offset[dep] = kctx.ptr_offset[dep - 1] + pn * sizeof(fpr);
                kctx.depth = dep;
                return 0;
            }
        }
    }

    /* Non-leaf: LDLmv on g_buf, emit l10, splits */
    fpr *g0 = g_buf, *g1 = g_buf + n;
    size_t hn_l = n >> 1;
    Zf(poly_LDLmv_fft)(tmp_stage, tree_stage, g0, g1, g0, logn);
    emit_node_into(tree_stage_b, n * sizeof(fpr));
    *out_node_len = n * sizeof(fpr) + NODE_MAC_LEN;
    Zf(poly_split_fft)(g1, g1 + hn_l, g0, logn);
    Zf(poly_split_fft)(g0, g0 + hn_l, tmp_stage, logn);
    kctx.child_phase[dep] = 0;
    dep++;
    kctx.ptr_offset[dep] = kctx.ptr_offset[dep - 1];
    kctx.depth = dep;
    return 0;
}

/* ===================================================================
 * Main: orchestrate the wire production
 * =================================================================== */

#define L0_RECORD_SZ    (FN * sizeof(fpr) + NODE_MAC_LEN)
#define MAX_NODE_SZ     (FN * sizeof(fpr) + NODE_MAC_LEN)

int main(void) {
    unsigned old_cw = set_fpu_cw(2);

    /* 1. Read the seed */
    FILE *f = fopen("/tmp/falcon_seed.bin", "rb");
    if (!f) { perror("open seed"); return 1; }
    if (fread(g_zknox.falcon_seed, 1, 32, f) != 32) {
        perror("read seed"); return 1;
    }
    fclose(f);

    fprintf(stderr, "Seed: ");
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", g_zknox.falcon_seed[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "Variant: Falcon-%d (FLOGN=%d, FN=%d)\n", FALCON_VARIANT, FLOGN, FN);

    /* 2. Run keygen with the SHAKE seed → f, g, F, G, h */
    inner_shake256_context rng;
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, g_zknox.falcon_seed, 32);
    inner_shake256_flip(&rng);

    static uint8_t tmp[400000];
    static uint16_t h[FN];
    Zf(keygen)(&rng,
               g_zknox.falcon_f, g_zknox.falcon_g,
               g_zknox.falcon_F, g_zknox.falcon_G,
               h, FLOGN, tmp);

    fprintf(stderr, "h[0..7]: ");
    for (int i = 0; i < 8; i++) fprintf(stderr, "%u ", h[i]);
    fprintf(stderr, "\n");

    /* Save h as raw little-endian uint16 */
    f = fopen("/tmp/falcon_h_raw.bin", "wb");
    fwrite(h, sizeof(uint16_t), FN, f);
    fclose(f);

    /* 3. compute_l0_phase */
    uint8_t l0_record[L0_RECORD_SZ];
    compute_l0_phase(l0_record);
    fprintf(stderr, "L0 record: %zu B\n", (size_t)L0_RECORD_SZ);

    /* 4. Walk right subtree, collect records sequentially */
    prep_right_phase();
    uint8_t right_buf[200000];  /* Falcon-1024 max ~57328, Falcon-512 max ~26608 */
    size_t right_off = 0;
    while (1) {
        size_t node_len;
        int done = walker_step(1, 3, &node_len);
        memcpy(right_buf + right_off, WORK_BUF + 1 * SLOT_BYTES, node_len);
        right_off += node_len;
        if (done) break;
    }
    fprintf(stderr, "Right subtree: %zu B\n", right_off);

    /* 5. Walk left subtree */
    prep_left_phase();
    uint8_t left_buf[200000];
    size_t left_off = 0;
    while (1) {
        size_t node_len;
        int done = walker_step(0, 1, &node_len);
        memcpy(left_buf + left_off, WORK_BUF + 0 * SLOT_BYTES, node_len);
        left_off += node_len;
        if (done) break;
    }
    fprintf(stderr, "Left subtree: %zu B\n", left_off);

    /* 6. Concatenate the wire and save */
    size_t wire_size = L0_RECORD_SZ + right_off + left_off;
    uint8_t *wire = malloc(wire_size);
    memcpy(wire, l0_record, L0_RECORD_SZ);
    memcpy(wire + L0_RECORD_SZ, right_buf, right_off);
    memcpy(wire + L0_RECORD_SZ + right_off, left_buf, left_off);

    f = fopen("/tmp/falcon_wire.bin", "wb");
    fwrite(wire, 1, wire_size, f);
    fclose(f);
    fprintf(stderr, "Wire: %zu B → /tmp/falcon_wire.bin\n", wire_size);

    free(wire);
    set_fpu_cw(old_cw);
    return 0;
}
