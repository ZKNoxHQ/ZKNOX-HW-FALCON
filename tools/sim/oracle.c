/* Host oracle: Falcon Round 3 verification built on the low-RAM core's own primitives
 * (Falcon-mode hash_to_point: SHAKE256(nonce || msg), big-endian words; NTT mod q).
 *   s1 = c - s2*h mod q (centered), accept iff ||s1||^2 + ||s2||^2 <= l2bound[logn]. */
#include <stdint.h>
#include <string.h>
#include "fndsa_inner.h"

int oracle_verify(unsigned logn, const uint16_t *h_raw, const uint8_t *nonce, const uint8_t *msg, size_t msg_len,
                  const int16_t *s2, uint32_t *sqn_out) {
    static uint16_t c[1024], h[1024], t[1024];
    size_t n = (size_t)1 << logn;
    hash_to_point(logn, nonce, msg, msg_len, c);      /* ext: 0..q-1 */
    memcpy(h, h_raw, 2 * n); mqpoly_ext_to_int(logn, h); mqpoly_int_to_ntt(logn, h);
    for (size_t i = 0; i < n; i++) t[i] = (uint16_t)s2[i];
    mqpoly_signed_to_int(logn, t); mqpoly_int_to_ntt(logn, t); mqpoly_mul_ntt(logn, t, h); mqpoly_ntt_to_int(logn, t);
    mqpoly_ext_to_int(logn, c); mqpoly_sub(logn, c, t); mqpoly_int_to_ext(logn, c);   /* c = s1, ext */
    uint64_t sqn = 0;
    for (size_t i = 0; i < n; i++) {
        int32_t v = c[i] > 6144 ? (int32_t)c[i] - 12289 : (int32_t)c[i];
        sqn += (uint64_t)(v * v) + (uint64_t)((int32_t)s2[i] * s2[i]);
    }
    if (sqn_out) *sqn_out = (uint32_t)sqn;
    return sqn <= (logn == 9 ? 34034726u : 70265242u);
}
