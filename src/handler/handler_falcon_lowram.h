/*
 * handler_falcon_lowram.h — Falcon (Round 3) APDUs on the c-fn-dsa-alt core.
 *
 * All INS take P2 = logn (9 = Falcon-512, 10 = Falcon-1024).
 *
 *   0x50 FALCON_LR_KEYGEN   P1=0 (P1=1 forces a recomputation, for
 *        benchmarking). Makes the key of the degree available: derives the
 *        SLIP-10 seed and runs the fixed-point keygen (~22.6 KB temp for 1024)
 *        unless the key is already there (RAM session key by default, NVM
 *        record with FALCON_LR_PERSIST_KEY=1).
 *        Response: first 255 bytes of h (uint16 host order).
 *   0x51 FALCON_LR_GET_PK   P1=chunk index. h in 255-byte chunks (2n bytes).
 *   0x53 FALCON_LR_SIGN     P1 = 0x00 INIT | 0x06 FEED_MSG (32 bytes) |
 *        0x08 FEED_SEED (40 bytes, deterministic/test) | 0x09 GEN_SEED (TRNG) |
 *        0x10 SIGN_ALL (whole signature, ~20.5 KB temp for 1024) |
 *        0x91 GET_NONCE (40 bytes). No explicit KEYGEN needed: the key is
 *        regenerated (or read from NVM) on demand.
 *   0x54 FALCON_LR_GET_SIG  P1=chunk index. s2 raw int16 host order (2n bytes).
 *        Falcon verification: c = hash_to_point(SHAKE256(nonce || msg)),
 *        s1 = c - s2*h mod q, ||(s1, s2)||^2 <= Round 3 bound.
 */
#pragma once

#include <stdint.h>
#include "buffer.h"

int handler_falcon_lr_keygen(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon_lr_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon_lr_sign(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon_lr_get_sig(buffer_t *cdata, uint8_t p1, uint8_t p2);
