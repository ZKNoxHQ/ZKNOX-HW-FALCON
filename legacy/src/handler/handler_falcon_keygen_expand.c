/*
 * handler_falcon_keygen_expand.c — Falcon-1024 streaming keygen expansion
 *                                   for Ledger Nano S Plus (v0.5.2)
 *
 * Consumes the in-BSS (f, g, F, G) produced by the previous FALCON_KEYGEN
 * and streams out a 122864 B v0.4.0 wire blob that the sign-side
 * FEED_SWAP + FEED_TREE_STREAM can consume verbatim.
 *
 * Algorithm (cross-validated byte-for-byte against Zf(expand_privkey) +
 * v0.4.1 walker in falcon1024_expand_stream_sim.c, and against the APDU
 * emulator in falcon1024_keygen_expand_emul.c — 3/3 keys byte-identical
 * to the testvec JSON):
 *
 *   Phase 0 (Gram) : G00/G01/G11 computed in 32 KB of work_buf, with b00,
 *                    b01, b10, b11 re-materialized on demand from the
 *                    4 KB int8 key storage in g_zknox.falcon_{f,g,F,G}
 *                    (8 FFTs total, ~640 ms on Cortex-M33).
 *   Phase 1 (L10)  : custom ldlmv_fft_inplace with l10 aliased onto G01,
 *                    d11 aliased onto G11. Emit L0 = g01 slot contents
 *                    (encrypted in place). Splits produce split(d11)
 *                    (feeds RIGHT) and split(d00) (feeds LEFT).
 *   Phase 2 (L9–0) : iterative DFS walker (state-machine pattern, same
 *                    as sign handler's dfs_feed). Each walker_step()
 *                    produces one node; leaf normalization fused into
 *                    the emit step.
 *
 * Wire layout (matches what FEED_SWAP + FEED_TREE_STREAM expect):
 *     0      L0 ct    8192 B     (v0.4.0 authenticated L0)
 *     8192   L0 tag     16 B
 *     8208   right subtree records (57328 B = 1023 × ct||tag)
 *     65536  left  subtree records (57328 B)
 *    122864  TOTAL
 *
 * APDU protocol:
 *     P1=0x00 COMPUTE_L0      no data   Gram + Level-10 LDL, stage L0
 *     P1=0x01 GET_L0 P2=idx   no data   pull 255 B chunk at offset idx*255
 *                                       of the 8208 B L0 record
 *     P1=0x02 PREP_RIGHT      no data   splits + right-walker init,
 *                                       stage first right node
 *     P1=0x03 GET_NEXT_R      no data   next sequential chunk of right
 *                                       subtree stream (<=255 B)
 *     P1=0x04 PREP_LEFT       no data   swap walker to left subtree,
 *                                       stage first left node
 *     P1=0x05 GET_NEXT_L      no data   next sequential chunk of left
 *                                       subtree stream (<=255 B)
 *
 * Memory: 4 × 8 KB slots + ~250 B state inside g_zknox._falcon_sign_area
 * (unioned with sign sctx; keygen-expand and sign are never concurrent).
 *
 * Preconditions:
 *     - g_zknox.falcon_ready must be 1 (i.e. FALCON_KEYGEN ran).
 *     - The host must have already pulled the public key via FALCON_GET_PK
 *       BEFORE calling FALCON_KEYGEN_EXPAND; the expand overwrites the
 *       _falcon_sign_area region where h was staged.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "sw.h"
#include "os.h"
#include "buffer.h"
#include "globals.h"
#include "send_response.h"
#include "zkn_errors.h"
#include "handler_falcon_keygen_expand.h"
#include "falcon_inner.h"

#define FLOGN        10
#define FN           (1 << FLOGN)                /* 1024 */
#define HN           (FN >> 1)                    /* 512  */
#define DFS_LOGN     9
#define NODE_MAC_LEN 16
#define SLOT_BYTES   (FN * sizeof(fpr))           /* 8192 */
#define N_SLOTS      4                             /* 32768 B work_buf */

/* ================================================================
 * Sub-phase state machine
 * ================================================================ */
enum {
    KE_IDLE = 0,
    KE_L0_STAGED,         /* L0 [ct(8192) || tag in kctx.l0_tag] ready */
    KE_WALK_RIGHT,         /* right subtree walker active */
    KE_WALK_LEFT,          /* left subtree walker active */
    KE_DONE
};

/* ================================================================
 * Keygen-expand context.
 *
 * The 32 KB work_buf lives inside g_zknox._falcon_sign_area (aliased,
 * sized for FALCON_SIGN_BSS_SIZE = 32768 B since v0.6.0). The small
 * walker state (~150 B) is kept in a SEPARATE BSS variable so the
 * union doesn't have to grow beyond the work_buf size — bumping the
 * union beyond 32768 hits the SDK linker's stack section limit on
 * Nano S+.
 * ================================================================ */
typedef struct {
    int     phase;
    int     depth;
    int     child_phase[DFS_LOGN];
    size_t  ptr_offset[DFS_LOGN + 1];
    size_t  cum_off;
    size_t  node_shipped;
    size_t  node_len;
    uint8_t tree_key[32];
    uint8_t mac_key[32];
    uint8_t l0_tag[NODE_MAC_LEN];
} falcon_keygen_expand_state_t;

/* Persistent across APDUs (BSS). Small (~250 B). */
static falcon_keygen_expand_state_t g_kstate;

/* Work buffer aliased onto the existing sign area. Exactly 4 slots of
 * 8192 B = 32768 B = sizeof(g_zknox._falcon_sign_area). */
#define WORK_BUF ((uint8_t *)g_zknox._falcon_sign_area)
#define SLOT(i)  ((fpr *)(WORK_BUF + (size_t)(i) * SLOT_BYTES))

_Static_assert(N_SLOTS * SLOT_BYTES <= FALCON_SIGN_BSS_SIZE,
               "work_buf exceeds _falcon_sign_area");

/* Backward-compat shim: the rest of the file refers to fields via `kctx.X`.
 * Redirect kctx.X to g_kstate.X. */
#define kctx g_kstate

/* ================================================================
 * Tree encryption — uses a local XOF (one per call, no persistent state).
 * Same primitives as handler_falcon_sign.c; MUST stay byte-compatible.
 * ================================================================ */
static void off_to_le8(size_t byte_offset, uint8_t off_le[8]) {
    off_le[0] = (uint8_t)(byte_offset);
    off_le[1] = (uint8_t)(byte_offset >> 8);
    off_le[2] = (uint8_t)(byte_offset >> 16);
    off_le[3] = (uint8_t)(byte_offset >> 24);
    off_le[4] = 0; off_le[5] = 0; off_le[6] = 0; off_le[7] = 0;
}

static void derive_tree_key(uint8_t key[32], const uint8_t seed[32]) {
    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, (const uint8_t *)"falcon-tree-key", 15);
    Zf(i_shake256_inject)(&xof, seed, 32);
    Zf(i_shake256_flip)(&xof);
    Zf(i_shake256_extract)(&xof, key, 32);
}

static void derive_tree_mac_key(uint8_t mkey[32], const uint8_t seed[32]) {
    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, (const uint8_t *)"falcon-tree-mac", 15);
    Zf(i_shake256_inject)(&xof, seed, 32);
    Zf(i_shake256_flip)(&xof);
    Zf(i_shake256_extract)(&xof, mkey, 32);
}

static void tree_xor_inplace(const uint8_t key[32], uint8_t *data,
                              size_t len, size_t byte_offset) {
    uint8_t off_le[8]; off_to_le8(byte_offset, off_le);
    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, key, 32);
    Zf(i_shake256_inject)(&xof, off_le, 8);
    Zf(i_shake256_flip)(&xof);
    uint8_t ks[64]; size_t pos = 0;
    while (pos < len) {
        size_t c = len - pos; if (c > 64) c = 64;
        Zf(i_shake256_extract)(&xof, ks, c);
        for (size_t i = 0; i < c; i++) data[pos + i] ^= ks[i];
        pos += c;
    }
}

static void tree_compute_tag(const uint8_t mkey[32], const uint8_t *ct,
                              size_t len, size_t byte_offset,
                              uint8_t tag[NODE_MAC_LEN]) {
    uint8_t off_le[8]; off_to_le8(byte_offset, off_le);
    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, mkey, 32);
    Zf(i_shake256_inject)(&xof, off_le, 8);
    Zf(i_shake256_inject)(&xof, ct, len);
    Zf(i_shake256_flip)(&xof);
    Zf(i_shake256_extract)(&xof, tag, NODE_MAC_LEN);
}

/* Encrypt+tag a plaintext node in place. Target buf must have NODE_MAC_LEN
 * bytes after nb. Advances kctx.cum_off. */
static void emit_node_into(uint8_t *target_buf, size_t nb) {
    tree_xor_inplace(kctx.tree_key, target_buf, nb, kctx.cum_off);
    tree_compute_tag(kctx.mac_key, target_buf, nb, kctx.cum_off,
                     target_buf + nb);
    kctx.cum_off += nb;
}

/* ================================================================
 * On-demand key re-materialization — reloads one of (f,g,F,G) from the
 * 4 KB int8 BSS, FFT's it, optionally negates (b01 = -FFT(f), b11 = -FFT(F)).
 * ================================================================ */
static void rematerialize(fpr *dst, const int8_t *src, int do_neg) {
    for (size_t u = 0; u < FN; u++) dst[u] = fpr_of(src[u]);
    Zf(FFT)(dst, FLOGN);
    if (do_neg) Zf(poly_neg)(dst, FLOGN);
}

/* ================================================================
 * Phase 0 — Gram matrix in 32 KB, 8 FFTs of (f,g,F,G).
 *
 * Slot allocation on entry: any (we overwrite SLOT(0..3)).
 * Slot allocation on exit:  SLOT(0)=G00, SLOT(1)=G01, SLOT(2)=G11.
 *                            SLOT(3) is transient scratch.
 * ================================================================ */
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

/* ================================================================
 * Custom in-place LDLmv: l10 writes into g01's slot, d11 writes into
 * g11's slot. Per-iteration access pattern reads (g00,g01,g11) at
 * (u, u+hn) BEFORE writing (l10,d11) at the same indices, so aliasing
 * is safe (verified byte-for-byte in ldlmv_debug.c).
 *
 * Math is Zf(poly_LDLmv_fft) non-AVX path (fft.c:1184-1201), expanded
 * inline with explicit temporaries to avoid nested-macro shadowing,
 * and with l10's imaginary part NEGATED on store (per fft.c:1199 —
 * AVX2 path folds the negation into an FMSUB, scalar path does it
 * explicitly). Missing that fpr_neg cost us one debug iteration.
 * ================================================================ */
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

/* ================================================================
 * COMPUTE_L0 — Gram + Level-10 LDL + stage L0 for shipping.
 *
 * On exit: SLOT(0)=d00, SLOT(2)=d11 (both needed for prep_right_phase
 * splits), SLOT(1) contains the encrypted L0 ciphertext (8192 B),
 * kctx.l0_tag contains the 16 B tag.
 * ================================================================ */
static void compute_l0_phase(void) {
    kctx.cum_off = 0;

    /* Derive streaming keys from the persistent falcon_seed. */
    derive_tree_key(kctx.tree_key, g_zknox.falcon_seed);
    derive_tree_mac_key(kctx.mac_key, g_zknox.falcon_seed);

    gram_phase();
    ldlmv_fft_inplace(SLOT(0), SLOT(1), SLOT(2));

    /* Encrypt L0 (= SLOT(1)) in place; tag into kctx.l0_tag (NOT at
     * SLOT(1)+8192, which would overflow into SLOT(2) and corrupt d11). */
    tree_xor_inplace(kctx.tree_key, (uint8_t *)SLOT(1),
                     FN * sizeof(fpr), kctx.cum_off);
    tree_compute_tag(kctx.mac_key, (uint8_t *)SLOT(1),
                     FN * sizeof(fpr), kctx.cum_off, kctx.l0_tag);
    kctx.cum_off += FN * sizeof(fpr);
}

/* ================================================================
 * PREP_RIGHT — splits d00/d11 in place, inits right-subtree walker.
 *
 * On entry : SLOT(0)=d00, SLOT(2)=d11.
 * On exit  : SLOT(0)=split(d11) [feeds RIGHT walker], SLOT(2)=split(d00)
 *            [pinned for LEFT later], SLOT(1) and SLOT(3) free.
 *            Walker state positioned at depth 0 of right subtree.
 * ================================================================ */
static void prep_right_phase(void) {
    fpr *TMP = SLOT(3);
    /* TMP ← split(d00) */
    Zf(poly_split_fft)(TMP, TMP + HN, SLOT(0), FLOGN);
    /* SLOT(0) ← split(d11) (in place overwrite) */
    Zf(poly_split_fft)(SLOT(0), SLOT(0) + HN, SLOT(2), FLOGN);
    /* SLOT(2) ← memcpy(TMP) = split(d00) */
    memcpy(SLOT(2), TMP, FN * sizeof(fpr));

    kctx.depth = 0;
    memset(kctx.child_phase, 0, sizeof kctx.child_phase);
    kctx.ptr_offset[0] = 0 * SLOT_BYTES;  /* walker reads from SLOT(0) */
}

static void prep_left_phase(void) {
    kctx.depth = 0;
    memset(kctx.child_phase, 0, sizeof kctx.child_phase);
    kctx.ptr_offset[0] = 2 * SLOT_BYTES;  /* walker reads from SLOT(2) */
}

/* ================================================================
 * Unified walker step — produces exactly ONE DFS node, staged as
 * [ct || tag] at WORK_BUF + tree_slot*SLOT_BYTES (length in
 * kctx.node_len). Advances walker state.
 *
 *   RIGHT: walker_step(1, 3, KE_WALK_LEFT)  — tree=SLOT(1), tmp=SLOT(3)
 *   LEFT : walker_step(0, 1, KE_DONE)       — tree=SLOT(0), tmp=SLOT(1)
 *
 * On end-of-subtree: kctx.phase transitions to `end_phase` and walker
 * is reset (depth=0) ready for the next subtree's prep call.
 * ================================================================ */
static void walker_step(int tree_slot, int tmp_slot, int end_phase) {
    int dep = kctx.depth;
    unsigned logn = DFS_LOGN - (unsigned)dep;
    size_t n = (size_t)1 << logn;
    fpr     *g_buf        = (fpr *)(WORK_BUF + kctx.ptr_offset[dep]);
    uint8_t *tree_stage_b = WORK_BUF + (size_t)tree_slot * SLOT_BYTES;
    fpr     *tree_stage   = (fpr *)tree_stage_b;
    fpr     *tmp_stage    = (fpr *)(WORK_BUF + (size_t)tmp_slot * SLOT_BYTES);

    if (n == 1) {
        /* Leaf: normalize + emit */
        tree_stage[0] = fpr_mul(fpr_sqrt(g_buf[0]), fpr_inv_sigma);
        emit_node_into(tree_stage_b, sizeof(fpr));
        kctx.node_len = sizeof(fpr) + NODE_MAC_LEN;
        /* Bubble up; next call will start at the new position. */
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

    /* Non-leaf: LDLmv → tree_stage=l10, tmp_stage=d11; emit l10; splits. */
    fpr *g0 = g_buf, *g1 = g_buf + n;
    size_t hn_l = n >> 1;
    Zf(poly_LDLmv_fft)(tmp_stage, tree_stage, g0, g1, g0, logn);
    emit_node_into(tree_stage_b, n * sizeof(fpr));
    kctx.node_len = n * sizeof(fpr) + NODE_MAC_LEN;
    Zf(poly_split_fft)(g1, g1 + hn_l, g0, logn);
    Zf(poly_split_fft)(g0, g0 + hn_l, tmp_stage, logn);
    kctx.child_phase[dep] = 0;
    dep++;
    kctx.ptr_offset[dep] = kctx.ptr_offset[dep - 1];  /* descend into RIGHT child */
    kctx.depth = dep;
}

/* ================================================================
 * APDU dispatcher
 * ================================================================ */
int handler_falcon_keygen_expand(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    ZKN_ERROR_INIT();

    /* All sub-phases require the key to have been derived already. */
    if (!g_zknox.falcon_ready) return io_send_sw(SWO_INCORRECT_DATA);

    switch (p1) {
    case 0x00: {  /* COMPUTE_L0 */
        if (p2 != 0 || cdata->size != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        compute_l0_phase();
        kctx.phase = KE_L0_STAGED;
        io_send_sw(SWO_SUCCESS);
        break;
    }
    case 0x01: {  /* GET_L0, P2 = chunk index into the 8208 B L0 record */
        if (kctx.phase != KE_L0_STAGED) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        size_t ct_sz = FN * sizeof(fpr);              /* 8192 */
        size_t total = ct_sz + NODE_MAC_LEN;           /* 8208 */
        size_t off   = (size_t)p2 * 255;
        if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
        size_t chunk = total - off; if (chunk > 255) chunk = 255;
        /* Assemble the chunk: bytes in [0, ct_sz) come from SLOT(1),
         * bytes in [ct_sz, total) come from kctx.l0_tag. */
        uint8_t tmp[255];
        for (size_t i = 0; i < chunk; i++) {
            size_t pos = off + i;
            tmp[i] = (pos < ct_sz)
                   ? ((uint8_t *)SLOT(1))[pos]
                   : kctx.l0_tag[pos - ct_sz];
        }
        io_send_response_pointer(tmp, chunk, SWO_SUCCESS);
        break;
    }
    case 0x02: {  /* PREP_RIGHT */
        if (p2 != 0 || cdata->size != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (kctx.phase != KE_L0_STAGED) return io_send_sw(SWO_INCORRECT_P1_P2);
        prep_right_phase();
        kctx.phase = KE_WALK_RIGHT;
        walker_step(1, 3, KE_WALK_LEFT);   /* stage first right node */
        kctx.node_shipped = 0;
        io_send_sw(SWO_SUCCESS);
        break;
    }
    case 0x03: {  /* GET_NEXT_R — sequential chunks of right subtree */
        if (p2 != 0 || cdata->size != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (kctx.phase != KE_WALK_RIGHT && kctx.phase != KE_WALK_LEFT)
            return io_send_sw(SWO_INCORRECT_P1_P2);
        if (kctx.node_shipped >= kctx.node_len) {
            /* Current node shipped; advance walker for the next one. */
            if (kctx.phase == KE_WALK_RIGHT) {
                walker_step(1, 3, KE_WALK_LEFT);
                kctx.node_shipped = 0;
            } else {
                /* Walker already transitioned to LEFT — host should call
                 * PREP_LEFT + GET_NEXT_L now, not GET_NEXT_R. */
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
        }
        size_t remaining = kctx.node_len - kctx.node_shipped;
        size_t chunk = remaining > 255 ? 255 : remaining;
        uint8_t *src = (uint8_t *)SLOT(1) + kctx.node_shipped;
        kctx.node_shipped += chunk;
        io_send_response_pointer(src, chunk, SWO_SUCCESS);
        break;
    }
    case 0x04: {  /* PREP_LEFT */
        if (p2 != 0 || cdata->size != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (kctx.phase != KE_WALK_LEFT) return io_send_sw(SWO_INCORRECT_P1_P2);
        prep_left_phase();
        walker_step(0, 1, KE_DONE);        /* stage first left node */
        kctx.node_shipped = 0;
        io_send_sw(SWO_SUCCESS);
        break;
    }
    case 0x05: {  /* GET_NEXT_L — sequential chunks of left subtree */
        if (p2 != 0 || cdata->size != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
        if (kctx.phase != KE_WALK_LEFT && kctx.phase != KE_DONE)
            return io_send_sw(SWO_INCORRECT_P1_P2);
        if (kctx.node_shipped >= kctx.node_len) {
            if (kctx.phase == KE_DONE) {
                /* Nothing more to produce; host should stop asking. */
                return io_send_sw(SWO_INCORRECT_DATA);
            }
            walker_step(0, 1, KE_DONE);
            kctx.node_shipped = 0;
        }
        size_t remaining = kctx.node_len - kctx.node_shipped;
        size_t chunk = remaining > 255 ? 255 : remaining;
        uint8_t *src = (uint8_t *)SLOT(0) + kctx.node_shipped;
        kctx.node_shipped += chunk;
        io_send_response_pointer(src, chunk, SWO_SUCCESS);
        break;
    }
    default:
        io_send_sw(SWO_INCORRECT_P1_P2);
        break;
    }

    ZKN_ERROR_CLOSE_SEND();
}
