/*
 * falcon_lowram_nvm.h — persistent Falcon key records for the c-fn-dsa-alt core.
 *
 * One record per degree:  key_id | f | g | F | h | fmt | ready
 *   key_id = SHAKE256("falcon-key-id" || seed, 32); the seed itself is not
 *            stored, it is re-derived (SLIP-10) when a session needs it.
 *   f, g, F  raw int8 (contiguous: exactly what the signing core reads)
 *   h        public key, coefficient form, uint16 host order
 *   fmt      record format (bump when the key layout changes)
 *   ready    written last; cleared before a record is rewritten
 * No G (the core recomputes G mod q), no LDL tree (the core has none).
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "fndsa_inner.h"   /* shake_* */

#define FALCON_LR_NVM_FMT 1

#define FALCON_LR_KEY_T(N, name)     \
    typedef struct {                 \
        uint8_t  key_id[32];         \
        int8_t   f[N];               \
        int8_t   g[N];               \
        int8_t   F[N];               \
        uint16_t h[N];               \
        uint8_t  fmt;                \
        uint8_t  ready;              \
    } name

FALCON_LR_KEY_T(512,  falcon_lr_key512_t);
FALCON_LR_KEY_T(1024, falcon_lr_key1024_t);

extern const falcon_lr_key512_t  N_falcon_lr_key_512_storage;
extern const falcon_lr_key1024_t N_falcon_lr_key_1024_storage;

static inline void falcon_lr_key_id(uint8_t id[32], const uint8_t seed[32]) {
    shake_context sc;
    shake_init(&sc, 256);
    shake_inject(&sc, (const uint8_t *)"falcon-key-id", 13);
    shake_inject(&sc, seed, 32);
    shake_flip(&sc);
    shake_extract(&sc, id, 32);
}

static inline int falcon_lr_ct_eq32(const uint8_t *a, const uint8_t *b) {
    uint8_t d = 0;
    for (size_t i = 0; i < 32; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* NVM records are const for the compiler and written by the OS: read the
 * state bytes through volatile (same idiom as N_storage in the SDK). */
#define FALCON_LR_NVM_U8(field) (*(const volatile uint8_t *)&(field))
#define FALCON_LR_KEY_OK(k, id) \
    (FALCON_LR_NVM_U8((k)->ready) == 1 && FALCON_LR_NVM_U8((k)->fmt) == FALCON_LR_NVM_FMT && \
     falcon_lr_ct_eq32((k)->key_id, (id)))
