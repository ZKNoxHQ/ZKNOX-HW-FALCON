/* Host oracle on the legacy reference library (compiled verify-only): Falcon hash_to_point + verify_raw. */
#include <stdint.h>
#include <string.h>
#include "inner.h"
int oracle_verify(unsigned logn, const uint16_t *h_raw, const uint8_t *nonce, const uint8_t *msg, size_t msg_len, const int16_t *s2, uint32_t *sqn_out) {
    static uint16_t h[1024], hm[1024]; static uint8_t tmp[8192];
    size_t n = (size_t)1 << logn;
    memcpy(h, h_raw, 2 * n);
    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof); Zf(i_shake256_inject)(&xof, nonce, 40); Zf(i_shake256_inject)(&xof, msg, msg_len);
    Zf(i_shake256_flip)(&xof); Zf(hash_to_point_vartime)(&xof, hm, logn);
    if (sqn_out) {   /* ||s1||^2 + ||s2||^2 (schoolbook) */
        static int64_t acc[2048]; memset(acc, 0, sizeof acc); uint64_t sqn = 0;
        for (size_t i = 0; i < n; i++) for (size_t j = 0; j < n; j++) { int64_t p = (int64_t)s2[i] * h_raw[j]; size_t k = i + j; if (k >= n) acc[k - n] -= p; else acc[k] += p; }
        for (size_t i = 0; i < n; i++) { int64_t v = ((int64_t)hm[i] - acc[i]) % 12289; if (v < 0) v += 12289; if (v > 6144) v -= 12289; sqn += (uint64_t)(v * v) + (uint64_t)((int64_t)s2[i] * s2[i]); }
        *sqn_out = (uint32_t)sqn;
    }
    Zf(to_ntt_monty)(h, logn);
    return Zf(verify_raw)(hm, s2, h, logn, tmp);
}
