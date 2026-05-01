/*
 * handler_falcon512_keygen_expand.h — Falcon-512 streaming keygen-expand
 * public API.
 *
 * Companion to handler_falcon_keygen_expand.h (Falcon-1024 v0.7.0).
 */

#ifndef HANDLER_FALCON512_KEYGEN_EXPAND_H
#define HANDLER_FALCON512_KEYGEN_EXPAND_H

#include <stdint.h>
#include "buffer.h"

/* INS_FALCON512_KEYGEN_EXPAND (0x44)
 * Six P1 sub-commands (identical to Falcon-1024 INS 0x34):
 *   0x00 COMPUTE_L0, 0x01 GET_L0, 0x02 PREP_RIGHT,
 *   0x03 GET_NEXT_R, 0x04 PREP_LEFT, 0x05 GET_NEXT_L.
 * Total wire size for Falcon-512: 57328 B (vs 122864 B for Falcon-1024). */
int handler_falcon512_keygen_expand(buffer_t *cdata, uint8_t p1, uint8_t p2);

#endif /* HANDLER_FALCON512_KEYGEN_EXPAND_H */
