/*
 * handler_falcon_lowram.c — Falcon (Round 3) on Thomas Pornin's c-fn-dsa-alt core.
 *
 * RAM: everything runs in g_falcon_lr.area (FALCON_LR_AREA_SIZE bytes, 32-byte
 * aligned inside): keygen temp 22n+31, sign temp 20n+31, plus the encoded
 * key produced by the keygen (decoded to raw f, g, F, h before being
 * persisted). No LDL tree, no expand step, no host round trip.
 *
 * Key material: by default nothing at rest (FALCON_LR_PERSIST_KEY=0), the
 * key is regenerated from the SLIP-10 seed once per session and kept in RAM;
 * with FALCON_LR_PERSIST_KEY=1 it is persisted per degree in an NVM record
 * bound to key_id = SHAKE256("falcon-key-id" || seed). The seed itself is
 * never written to NVM.
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

#ifndef FALCON_LR_PERSIST_KEY
#define FALCON_LR_PERSIST_KEY 0
#endif
#include "fndsa.h"   /* src/falcon_lowram: c-fn-dsa-alt in Falcon mode */
#include "fndsa_inner.h"

/* ---- seed derivation (src/zknox/keys/derive.c) ---- */
cx_err_t falcon_derive_seed(uint8_t falcon_seed[32]);      /* "Falcon-1024 seed" */
cx_err_t falcon512_derive_seed(uint8_t falcon_seed[32]);   /* "Falcon-512 seed"  */

/* ===================================================================== *
 * Key material for the session
 *
 * Default (FALCON_LR_PERSIST_KEY=0): Ledger style, nothing at rest. The key
 * is regenerated from the SLIP-10 seed by the first APDU of the session that
 * needs it (fixed-point keygen, deterministic) and kept in RAM, in the tail
 * of the working area (outside the signing temp), until the app exits or
 * the other degree is requested.
 *
 * Option (FALCON_LR_PERSIST_KEY=1): the key is persisted per degree in an
 * NVM record bound to key_id = SHAKE256("falcon-key-id" || seed), so that a
 * fresh session signs without regenerating (see falcon_lowram_nvm.h).
 * ===================================================================== */

/* Degree-independent view of the key in use. */
typedef struct {
    const int8_t  *fgF;    /* f | g | F contiguous, 3n bytes */
    const uint16_t *h;     /* coefficient form, uint16 host order */
} key_view_t;

/* 32-byte aligned working area. */
static uint8_t *area_ptr(void) {
    return (uint8_t *)(((uintptr_t)g_falcon_lr.area + 31) & ~(uintptr_t)31);
}

/* Run the fixed-point keygen for `logn` from the session seed; leaves the
 * raw key f | g | F (3n) and h (2n) at `dst` (5n bytes, must not overlap the
 * keygen temp [area, area + 22n + 31) nor the encoded key kept at the end
 * of the area). Returns 1 on success. */
static int run_keygen(unsigned logn, uint8_t *dst) {
    size_t n = (size_t)1 << logn;
    size_t tmp_len = 22 * n + 31;
    size_t sk_len = FNDSA_SIGN_KEY_SIZE(logn), vk_len = FNDSA_VRFY_KEY_SIZE(logn);
    uint8_t *area = area_ptr();
    uint8_t *sk = area + FALCON_LR_AREA_SIZE - 64 - sk_len - vk_len;   /* encoded outputs at the end */
    uint8_t *vk = sk + sk_len;
    if (!fndsa_keygen_seeded_temp(logn, g_falcon_lr.seed, 32, sk, vk, area, tmp_len)) return 0;

    /* Decode into the (now free) head of the area, then move to dst. */
    int8_t *f = (int8_t *)area, *g = f + n, *F = g + n;
    uint16_t *h = (uint16_t *)(area + 3 * n);
    unsigned nbits = fg_nbits(logn);
    size_t flen = (nbits << logn) >> 3;
    trim_i8_decode(logn, sk + 1, f, nbits);
    trim_i8_decode(logn, sk + 1 + flen, g, nbits);
    memcpy(F, sk + 1 + 2 * flen, n);
    mqpoly_decode(logn, vk + 1, h);       /* FN-DSA public key: NTT form */
    mqpoly_ext_to_int(logn, h);
    mqpoly_ntt_to_int(logn, h);
    mqpoly_int_to_ext(logn, h);           /* Falcon public key: coefficients */
    explicit_bzero(sk, sk_len);           /* encoded private key no longer needed
                                             (wiped before dst is written: dst may overlap it) */
    memmove(dst, area, 5 * n);
    explicit_bzero(area, 5 * n);
    return 1;
}

/* Session seed for this degree (derived once), then key_id. */
static int session_seed(unsigned logn) {
    if (g_falcon_lr.seed_ready != logn) {
        cx_err_t e = (logn == 9) ? falcon512_derive_seed(g_falcon_lr.seed) : falcon_derive_seed(g_falcon_lr.seed);
        if (e != CX_OK) return 0;
        g_falcon_lr.seed_ready = (uint8_t)logn;
    }
    return 1;
}

#if !FALCON_LR_PERSIST_KEY
/* ---------------- RAM only: session key in the tail of the area ---------------- */

/* Raw key location: after the signing temp (20n + 31 <= 20 511), 5n bytes. */
#define SESSION_KEY_OFF 20544
static uint8_t *session_key_ptr(void) { return area_ptr() + SESSION_KEY_OFF; }

/* Make the key of degree `logn` available (regenerating it if needed or if
 * `force`); returns 1 and fills `kv` on success. */
static int get_key(unsigned logn, int force, key_view_t *kv) {
    if (logn != 9 && logn != 10) return 0;
    size_t n = (size_t)1 << logn;
    if (force || g_falcon_lr.key_logn != logn) {
        g_falcon_lr.key_logn = 0;
        g_falcon_lr.sig_ready = 0;
        if (!session_seed(logn)) return 0;
        if (!run_keygen(logn, session_key_ptr())) return 0;
        explicit_bzero(g_falcon_lr.seed, 32);     /* the seed is only needed by the keygen */
        g_falcon_lr.seed_ready = 0;
        g_falcon_lr.key_logn = (uint8_t)logn;
    }
    kv->fgF = (const int8_t *)session_key_ptr();
    kv->h = (const uint16_t *)(session_key_ptr() + 3 * n);
    return 1;
}

#else
/* ---------------- NVM persistence: key record per degree ---------------- */

const falcon_lr_key512_t  N_falcon_lr_key_512_storage = {0};
const falcon_lr_key1024_t N_falcon_lr_key_1024_storage = {0};
#define N_KEY512  ((const falcon_lr_key512_t *)PIC(&N_falcon_lr_key_512_storage))
#define N_KEY1024 ((const falcon_lr_key1024_t *)PIC(&N_falcon_lr_key_1024_storage))

typedef struct {
    const uint8_t *key_id; const int8_t *fgF; const uint16_t *h; const uint8_t *fmt; const uint8_t *ready;
} nvm_view_t;

static int nvm_view(unsigned logn, nvm_view_t *v) {
    if (logn == 9) {
        const falcon_lr_key512_t *k = N_KEY512;
        v->key_id = k->key_id; v->fgF = k->f; v->h = k->h; v->fmt = &k->fmt; v->ready = &k->ready; return 1;
    }
    if (logn == 10) {
        const falcon_lr_key1024_t *k = N_KEY1024;
        v->key_id = k->key_id; v->fgF = k->f; v->h = k->h; v->fmt = &k->fmt; v->ready = &k->ready; return 1;
    }
    return 0;
}

static int get_key(unsigned logn, int force, key_view_t *kv) {
    nvm_view_t nv;
    if (!nvm_view(logn, &nv) || !session_seed(logn)) return 0;
    uint8_t id[32];
    falcon_lr_key_id(id, g_falcon_lr.seed);
    int ok = FALCON_LR_NVM_U8(*nv.ready) == 1 && FALCON_LR_NVM_U8(*nv.fmt) == FALCON_LR_NVM_FMT &&
             falcon_lr_ct_eq32(nv.key_id, id);
    if (force || !ok) {
        /* New (or first) key for this seed: invalidate, compute, persist (`ready` last). */
        uint8_t zero = 0, one = 1, fmt = FALCON_LR_NVM_FMT;
        size_t n = (size_t)1 << logn;
        nvm_write((void *)nv.ready, &zero, 1);
        uint8_t *raw = area_ptr() + 20544;
        if (!run_keygen(logn, raw)) return 0;
        nvm_write((void *)nv.key_id, id, 32);
        nvm_write((void *)nv.fgF, raw, 3 * n);
        nvm_write((void *)nv.h, raw + 3 * n, 2 * n);
        nvm_write((void *)nv.fmt, &fmt, 1);
        nvm_write((void *)nv.ready, &one, 1);
        explicit_bzero(raw, 5 * n);
    }
    kv->fgF = nv.fgF;
    kv->h = nv.h;
    return 1;
}
#endif

/* ===================================================================== *
 * KEYGEN — P1 = 0: make the key available (regenerate only if needed);
 *          P1 = 1: force a fresh generation (benchmark).
 * ===================================================================== */
int handler_falcon_lr_keygen(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    key_view_t kv;
    if (p1 > 1 || (p2 != 9 && p2 != 10)) return io_send_sw(SWO_INCORRECT_P1_P2);
    if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
    if (!get_key(p2, p1 == 1, &kv)) return io_send_sw(SWO_INCORRECT_DATA);
    io_send_response_pointer((const uint8_t *)kv.h, 255, SWO_SUCCESS);
    return 0;
}

/* ===================================================================== *
 * GET_PK — h, uint16 host order, 255-byte chunks
 * ===================================================================== */
int handler_falcon_lr_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata;
    key_view_t kv;
    if (p2 != 9 && p2 != 10) return io_send_sw(SWO_INCORRECT_P1_P2);
    if (!get_key(p2, 0, &kv)) return io_send_sw(SWO_INCORRECT_DATA);
    size_t total = (size_t)2 << p2;
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
    if (logn != 9 && logn != 10) return io_send_sw(SWO_INCORRECT_P1_P2);

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
        key_view_t kv;
        if (!get_key(logn, 0, &kv)) return io_send_sw(SWO_INCORRECT_DATA);
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

