/*
 * handler_falcon512.h — Falcon-512 keygen + get_pk public API.
 *
 * Companion to handler_falcon.h (Falcon-1024). The two coexist in the
 * same firmware; they share g_zknox storage but mutually exclude at runtime.
 */

#ifndef HANDLER_FALCON512_H
#define HANDLER_FALCON512_H

#include <stdint.h>
#include "buffer.h"

/* INS_FALCON512_KEYGEN (0x40)
 * Derive Falcon-512 keypair from BIP-32 m/44'/9004'/0'/0/0 with modifier
 * "Falcon-512 seed". No payload. */
int handler_falcon512_keygen(buffer_t *cdata);

/* INS_FALCON512_GET_PK (0x41)
 * Read back the 1024 B public key (raw uint16_t[512] little-endian).
 * P1 = chunk index in 255 B blocks. */
int handler_falcon512_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2);

#endif /* HANDLER_FALCON512_H */
