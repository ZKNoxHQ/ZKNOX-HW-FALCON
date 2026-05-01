/*
 * handler_falcon.c — v0.6.0
 *
 * MIGRATION : the seed is no longer fed by the host. It is derived
 * on-device via SLIP-10 over Ed25519 along the hardened BIP-32 path
 *
 *     m / 44' / 9004' / 0' / 0 / 0
 *
 * with HMAC modifier "Falcon-1024 seed" for domain-separation against
 * the existing ML-DSA seed derivation (which uses "ML-DSA-44 seed" on
 * the same primitive). This means:
 *   - The host never sees the seed.
 *   - The Falcon key is recoverable from the device's 24 words
 *     deterministically.
 *   - Different SLIP-44 path → different seed, no collision with
 *     ECDSA / ML-DSA / etc.
 *
 * APDU contract change:
 *   FALCON_KEYGEN (0x30) :  Lc = 0   (was Lc = 32 with raw seed)
 *                           P1 = 0,  P2 = 0
 *
 * On success: device populates g_zknox.falcon_{seed,f,g,F,G}, stages
 * the public key h in _falcon_sign_area, sets falcon_ready = 1, returns
 * the first 255 B of h. Host then pulls the rest via FALCON_GET_PK.
 *
 * Key COMPATIBILITY warning: the keys produced by v0.6.0 are NOT
 * byte-compatible with keys produced by v0.5.x and earlier. Any wallet
 * holding pre-v0.6.0 Falcon keys must regenerate via this new keygen.
 * Old testvecs (falcon1024_keygen_expand_testvec.json with explicit
 * seed) cannot be used against this build — they assume a host-fed
 * seed which the device no longer accepts.
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
#include "zkn_errors.h"
#include "handler_falcon.h"
#include "handler_falcon_sign.h"
#include "falcon_inner.h"

#define FALCON_LOGN 10
#define FALCON_FN (1 << FALCON_LOGN)
/* h at END of sign area — keygen tmp uses [0..28671], h uses [..end].
 * Tmp/h non-overlap holds for FALCON_SIGN_BSS_SIZE >= 30720
 * (FALCON_KEYGEN_TEMP_10 = 28672, h = 2048 B). v0.5.2's bump to 33024
 * leaves comfortable headroom. */
#define FALCON_H_OFFSET (FALCON_SIGN_BSS_SIZE - FALCON_FN * (int)sizeof(uint16_t))
#define FALCON_H_PTR    ((uint16_t *)((uint8_t *)g_zknox._falcon_sign_area + FALCON_H_OFFSET))

/* SLIP-10/Ed25519-based 32-byte seed derivation (declaration matches
 * the existing mldsa_derive_seed pattern in zknox/keys/derive.c). */
extern cx_err_t falcon_derive_seed(uint8_t falcon_seed[32]);

int handler_falcon_keygen(buffer_t *cdata) {
    ZKN_ERROR_INIT();

    /* v0.6.0: APDU carries no data. Path is hard-coded in the derivation. */
    if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);

    cx_err_t derr = falcon_derive_seed(g_zknox.falcon_seed);
    if (derr != CX_OK) return io_send_sw((uint16_t)derr);

    inner_shake256_context rng;
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, g_zknox.falcon_seed, 32);
    inner_shake256_flip(&rng);

    size_t tmp_size;
    uint8_t *tmp = falcon_sign_get_tmp_buffer(&tmp_size);

    /* G is not stored persistently (saves 1024 B BSS).
     * Provide an ephemeral buffer inside _falcon_sign_area, just below h,
     * for falcon_keygen to write G into. After this handler returns, the
     * area is reused by subsequent operations and G is recomputed on
     * demand via Zf(complete_private). */
    int8_t *G_ephemeral = (int8_t *)((uint8_t *)g_zknox._falcon_sign_area
                                      + FALCON_H_OFFSET
                                      - FALCON_FN * sizeof(int8_t));
    falcon_keygen(&rng,
        g_zknox.falcon_f, g_zknox.falcon_g,
        g_zknox.falcon_F, G_ephemeral,
        FALCON_H_PTR, FALCON_LOGN, tmp);

    g_zknox.falcon_ready = 1;
    io_send_response_pointer((uint8_t *)FALCON_H_PTR, 255, SWO_SUCCESS);
    ZKN_ERROR_CLOSE_SEND();
}

int handler_falcon_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata;
    ZKN_ERROR_INIT();
    if (!g_zknox.falcon_ready) return io_send_sw(SWO_INCORRECT_DATA);
    uint8_t *pk = (uint8_t *)FALCON_H_PTR;
    size_t total = FALCON_FN * sizeof(uint16_t);
    size_t off = (size_t)p1 * 255;
    if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
    size_t chunk = p2 ? p2 : 255;
    if (off + chunk > total) chunk = total - off;
    io_send_response_pointer(pk + off, chunk, SWO_SUCCESS);
    ZKN_ERROR_CLOSE_SEND();
}
