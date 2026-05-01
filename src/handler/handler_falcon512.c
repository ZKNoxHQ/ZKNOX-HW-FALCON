/*
 * handler_falcon512.c — Falcon-512 keygen + get_pk for Ledger Nano S Plus.
 *
 * v0.1.0 — companion to handler_falcon.c (Falcon-1024 v0.7.0).
 *
 * Same architecture as Falcon-1024:
 *   - Seed derived on-device via SLIP-10 over Ed25519 along
 *     m / 44' / 9004' / 0' / 0 / 0 with HMAC modifier "Falcon-512 seed"
 *     (distinct from "Falcon-1024 seed" → different keys for the two
 *      variants, intentional domain separation).
 *   - Output public key is Falcon-512: raw uint16_t[512] = 1024 B.
 *   - Persistent material reuses g_zknox.falcon_{seed,f,g,F,G} (the int8_t
 *     arrays are sized [1024] but Falcon-512 only fills the first 512).
 *
 * APDU contract:
 *   FALCON512_KEYGEN  (0x40):  Lc = 0, P1 = 0, P2 = 0
 *   FALCON512_GET_PK  (0x41):  P1 = chunk index, returns up to 255 B
 *
 * Both Falcon-1024 (INS 0x30/0x31) and Falcon-512 (INS 0x40/0x41) coexist
 * in the same firmware; they share g_zknox storage but cannot be active
 * simultaneously (set falcon_ready = 1 on either KEYGEN; subsequent calls
 * to the wrong variant's GET_PK will return stale data).
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
#include "handler_falcon512.h"
#include "handler_falcon512_sign.h"
#include "handler_falcon_sign.h"  /* for shared falcon_sign_get_tmp_buffer */
#include "falcon_inner.h"

#define FALCON_LOGN 9
#define FALCON_FN   (1 << FALCON_LOGN)             /* 512 */

/* h sits at the end of the sign area. For Falcon-512: 512 * 2 = 1024 B.
 * The arithmetic is identical to handler_falcon.c — we just consume less. */
#define FALCON_H_OFFSET (FALCON_SIGN_BSS_SIZE - FALCON_FN * (int)sizeof(uint16_t))
#define FALCON_H_PTR    ((uint16_t *)((uint8_t *)g_zknox._falcon_sign_area + FALCON_H_OFFSET))

/* Variant-specific seed derivation. Defined in zknox/keys/derive_falcon512.c. */
extern cx_err_t falcon512_derive_seed(uint8_t falcon_seed[32]);

int handler_falcon512_keygen(buffer_t *cdata) {
    ZKN_ERROR_INIT();

    /* No payload: path is hard-coded in the derivation. */
    if (cdata->size != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);

    cx_err_t derr = falcon512_derive_seed(g_zknox.falcon_seed);
    if (derr != CX_OK) return io_send_sw((uint16_t)derr);

    inner_shake256_context rng;
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, g_zknox.falcon_seed, 32);
    inner_shake256_flip(&rng);

    size_t tmp_size;
    uint8_t *tmp = falcon_sign_get_tmp_buffer(&tmp_size);
    /* falcon_keygen writes into f, g, F, G — sized [1024], we only use
     * indices [0..511] for Falcon-512. The remaining 512 bytes of each
     * array are irrelevant. */
    falcon_keygen(&rng,
        g_zknox.falcon_f, g_zknox.falcon_g,
        g_zknox.falcon_F, g_zknox.falcon_G,
        FALCON_H_PTR, FALCON_LOGN, tmp);

    g_zknox.falcon_ready = 1;
    /* Return the first chunk (255 B) of h. Falcon-512 h is 1024 B total,
     * so caller will issue 4 GET_PK calls (255+255+255+259... actually 4 chunks
     * with the last one being 259 B if we don't cap to 255). The original
     * Falcon-1024 protocol caps at 255 — we keep the same convention. */
    io_send_response_pointer((uint8_t *)FALCON_H_PTR, 255, SWO_SUCCESS);
    ZKN_ERROR_CLOSE_SEND();
}

int handler_falcon512_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata;
    ZKN_ERROR_INIT();
    if (!g_zknox.falcon_ready) return io_send_sw(SWO_INCORRECT_DATA);
    uint8_t *pk = (uint8_t *)FALCON_H_PTR;
    size_t total = FALCON_FN * sizeof(uint16_t);   /* 1024 */
    size_t off = (size_t)p1 * 255;
    if (off >= total) return io_send_sw(SWO_INCORRECT_P1_P2);
    size_t chunk = p2 ? p2 : 255;
    if (off + chunk > total) chunk = total - off;
    io_send_response_pointer(pk + off, chunk, SWO_SUCCESS);
    ZKN_ERROR_CLOSE_SEND();
}
