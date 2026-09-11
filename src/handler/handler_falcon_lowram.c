/*
 * handler_falcon_lowram.c — Falcon (Round 3) on Thomas Pornin's c-fn-dsa-alt core.
 *
 * RAM: everything runs in g_falcon_lr.area (FALCON_LR_AREA_SIZE bytes, 32-byte
 * aligned inside): keygen temp 22n+31, sign temp 20n+31, plus the encoded
 * key produced by the keygen (decoded to raw f, g, F, h before being
 * persisted). No LDL tree, no expand step, no host round trip.
 *
 * Key material at rest: NVM record per degree (falcon_lowram_nvm.h), bound to
 * key_id = SHAKE256("falcon-key-id" || seed). The seed is cached per session
 * in g_falcon_lr.seed (tag g_falcon_lr.seed_ready = logn) and never written to NVM.
 */
#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "buffer.h"
#include "io.h"

#include "../sw.h"
#include "../globals.h"
#include "handler_falcon_lowram.h"
#include "falcon_lowram_nvm.h"
#include "fndsa.h"   /* src/falcon_lowram: c-fn-dsa-alt in Falcon mode */
#include "fndsa_inner.h"

#if FALCON_CORE_LOWRAM

/* ---- seed derivation (src/zknox/keys/derive.c) ---- */
cx_err_t falcon_derive_seed(uint8_t falcon_seed[32]);      /* "Falcon-1024 seed" */
cx_err_t falcon512_derive_seed(uint8_t falcon_seed[32]);   /* "Falcon-512 seed"  */

/* ---- NVM ---- */
const falcon_lr_key512_t  N_falcon_lr_key_512_storage = {0};
const falcon_lr_key1024_t N_falcon_lr_key_1024_storage = {0};
#define N_KEY512  ((const falcon_lr_key512_t *)PIC(&N_falcon_lr_key_512_storage))
#define N_KEY1024 ((const falcon_lr_key1024_t *)PIC(&N_falcon_lr_key_1024_storage))

/* Degree-independent view of a key record. */
typedef struct {
    const uint8_t *key_id;
    const int8_t  *fgF;    /* f | g | F contiguous, 3n bytes */
    const uint16_t *h;
    const uint8_t *fmt;
    const uint8_t *ready;
} key_view_t;

static int key_view(unsigned logn, key_view_t *v) {
    if (logn == 9) {
        const falcon_lr_key512_t *k = N_KEY512;
        v->key_id = k->key_id; v->fgF = k->f; v->h = k->h; v->fmt = &k->fmt; v->ready = &k->ready;
        return 1;
    }
    if (logn == 10) {
        const falcon_lr_key1024_t *k = N_KEY1024;
        v->key_id = k->key_id; v->fgF = k->f; v->h = k->h; v->fmt = &k->fmt; v->ready = &k->ready;
        return 1;
    }
    return 0;
}

static int key_ok(const key_view_t *v, const uint8_t id[32]) {
    return FALCON_LR_NVM_U8(*v->ready) == 1 && FALCON_LR_NVM_U8(*v->fmt) == FALCON_LR_NVM_FMT &&
           falcon_lr_ct_eq32(v->key_id, id);
}

/* Session seed for this degree (derived once per session), then key_id. */
static int session_seed(unsigned logn, uint8_t id[32]) {
    if (g_falcon_lr.seed_ready != logn) {
        cx_err_t e = (logn == 9) ? falcon512_derive_seed(g_falcon_lr.seed) : falcon_derive_seed(g_falcon_lr.seed);
        if (e != CX_OK) return 0;
        g_falcon_lr.seed_ready = (uint8_t)logn;
    }
    falcon_lr_key_id(id, g_falcon_lr.seed);
    return 1;
}

/* 32-byte aligned temporary area. */
static uint8_t *area_ptr(void) {
    return (uint8_t *)(((uintptr_t)g_falcon_lr.area + 31) & ~(uintptr_t)31);
}

/* ===================================================================== *
 * KEYGEN
 * ===================================================================== */
int handler_falcon_lr_keygen(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    unsigned logn = p2;
    key_view_t kv;
    if (p1 != 0 || !key_view(logn, &kv)) return io_send_sw(SWO_INCORRECT_P1_P2);
    if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);

    uint8_t id[32];
    if (!session_seed(logn, id)) return io_send_sw(SWO_INCORRECT_DATA);
    if (key_ok(&kv, id)) {
        /* Same mnemonic, same key: nothing to compute. */
        io_send_response_pointer((const uint8_t *)kv.h, 255, SWO_SUCCESS);
        return 0;
    }

    /* New (or first) key for this seed: invalidate, compute, persist. */
    uint8_t zero = 0, one = 1, fmt = FALCON_LR_NVM_FMT;
    nvm_write((void *)kv.ready, &zero, 1);

    size_t n = (size_t)1 << logn;
    size_t tmp_len = 22 * n + 31;
    size_t sk_len = FNDSA_SIGN_KEY_SIZE(logn), vk_len = FNDSA_VRFY_KEY_SIZE(logn);
    uint8_t *area = area_ptr();
    uint8_t *sk = area + FALCON_LR_AREA_SIZE - 64 - sk_len - vk_len;   /* encoded outputs at the end */
    uint8_t *vk = sk + sk_len;
    if (!fndsa_keygen_seeded_temp(logn, g_falcon_lr.seed, 32, sk, vk, area, tmp_len)) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    /* Decode to raw f | g | F | h (5n bytes at the start of the area; the
     * temp is free now, the encoded key sits at the end). */
    int8_t *f = (int8_t *)area, *g = f + n, *F = g + n;
    uint16_t *h = (uint16_t *)(area + 3 * n + (n & 1));
    unsigned nbits = fg_nbits(logn);
    size_t flen = (nbits << logn) >> 3;
    trim_i8_decode(logn, sk + 1, f, nbits);
    trim_i8_decode(logn, sk + 1 + flen, g, nbits);
    memcpy(F, sk + 1 + 2 * flen, n);
    mqpoly_decode(logn, vk + 1, h);       /* FN-DSA public key: NTT form */
    mqpoly_ext_to_int(logn, h);
    mqpoly_ntt_to_int(logn, h);
    mqpoly_int_to_ext(logn, h);           /* Falcon public key: coefficients */

    nvm_write((void *)kv.key_id, id, 32);
    nvm_write((void *)kv.fgF, f, 3 * n);
    nvm_write((void *)kv.h, h, 2 * n);
    nvm_write((void *)kv.fmt, &fmt, 1);
    nvm_write((void *)kv.ready, &one, 1);

    explicit_bzero(area, 5 * n + 2);
    explicit_bzero(sk, sk_len);

    io_send_response_pointer((const uint8_t *)kv.h, 255, SWO_SUCCESS);
    return 0;
}

/* ===================================================================== *
 * GET_PK — h, uint16 host order, 255-byte chunks
 * ===================================================================== */
int handler_falcon_lr_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata;
    unsigned logn = p2;
    key_view_t kv;
    if (!key_view(logn, &kv)) return io_send_sw(SWO_INCORRECT_P1_P2);
    uint8_t id[32];
    if (!session_seed(logn, id) || !key_ok(&kv, id)) return io_send_sw(SWO_INCORRECT_DATA);

    size_t total = (size_t)2 << logn;
    size_t off = (size_t)p1 * 255;
    if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
    size_t chunk = total - off;
    if (chunk > 255) chunk = 255;
    io_send_response_pointer((const uint8_t *)kv.h + off, chunk, SWO_SUCCESS);
    return 0;
}

/* ===================================================================== *
 * SIGN
 * ===================================================================== */
int handler_falcon_lr_sign(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    unsigned logn = p2;
    key_view_t kv;
    if (!key_view(logn, &kv)) return io_send_sw(SWO_INCORRECT_P1_P2);

    switch (p1) {
    case 0x00: /* INIT */
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        g_falcon_lr.msg_ready = 0;
        g_falcon_lr.sseed_ready = 0;
        g_falcon_lr.sig_ready = 0;
        explicit_bzero(g_falcon_lr.out, sizeof g_falcon_lr.out);
        return io_send_sw(SWO_SUCCESS);

    case 0x06: /* FEED_MSG: 32 bytes (a hash of the payload) */
        if (cdata->size != 32) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(g_falcon_lr.msg, cdata->ptr, 32);
        g_falcon_lr.msg_ready = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x08: /* FEED_SEED: 40 bytes, deterministic signature (test / KAT) */
        if (cdata->size != 40) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        memcpy(g_falcon_lr.sign_seed, cdata->ptr, 40);
        g_falcon_lr.sseed_ready = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x09: /* GEN_SEED: 40 bytes from the TRNG */
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        cx_rng_no_throw(g_falcon_lr.sign_seed, 40);
        g_falcon_lr.sseed_ready = 1;
        return io_send_sw(SWO_SUCCESS);

    case 0x10: { /* SIGN_ALL */
        if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
        if (!g_falcon_lr.msg_ready || !g_falcon_lr.sseed_ready) return io_send_sw(SWO_INCORRECT_DATA);
        uint8_t id[32];
        if (!session_seed(logn, id) || !key_ok(&kv, id)) return io_send_sw(SWO_INCORRECT_DATA);
        size_t n = (size_t)1 << logn;
        size_t r = fndsa_falcon_sign_seeded_temp(logn, kv.fgF, g_falcon_lr.msg, 32,
                                                 g_falcon_lr.sign_seed, 40,
                                                 g_falcon_lr.out, sizeof g_falcon_lr.out,
                                                 area_ptr(), 20 * n + 31);
        explicit_bzero(area_ptr(), 20 * n + 31);
        if (r != 41 + 2 * n) return io_send_sw(SWO_INCORRECT_DATA);
        g_falcon_lr.sig_ready = (uint8_t)logn;
        g_falcon_lr.sseed_ready = 0;   /* one signature per seed */
        return io_send_sw(SWO_SUCCESS);
    }

    case 0x91: /* GET_NONCE */
        if (g_falcon_lr.sig_ready != logn) return io_send_sw(SWO_INCORRECT_DATA);
        io_send_response_pointer(g_falcon_lr.out + 1, 40, SWO_SUCCESS);
        return 0;

    default:
        return io_send_sw(SWO_INCORRECT_P1_P2);
    }
}

/* ===================================================================== *
 * GET_SIG — s2, int16 host order, 255-byte chunks
 * ===================================================================== */
int handler_falcon_lr_get_sig(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata;
    unsigned logn = p2;
    if (logn != 9 && logn != 10) return io_send_sw(SWO_INCORRECT_P1_P2);
    if (g_falcon_lr.sig_ready != logn) return io_send_sw(SWO_INCORRECT_DATA);
    size_t total = (size_t)2 << logn;
    size_t off = (size_t)p1 * 255;
    if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
    size_t chunk = total - off;
    if (chunk > 255) chunk = 255;
    io_send_response_pointer(g_falcon_lr.out + 41 + off, chunk, SWO_SUCCESS);
    return 0;
}

#endif /* FALCON_CORE_LOWRAM */
