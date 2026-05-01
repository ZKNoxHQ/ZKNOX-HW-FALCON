/*
 * handler_falcon512_sign.h — Falcon-512 streaming sign public API.
 *
 * Companion to handler_falcon_sign.h (Falcon-1024 v0.7.0). Same APDU
 * sub-command structure, same on-device hash_to_point, same FEED_SWAP /
 * GET_SWAP / FEED_TREE_STREAM protocol. Only the polynomial degree
 * differs (logn=9 vs logn=10).
 *
 * The shared helper falcon_sign_get_tmp_buffer() lives in
 * handler_falcon_sign.c and is reused by both variants.
 */

#ifndef HANDLER_FALCON512_SIGN_H
#define HANDLER_FALCON512_SIGN_H

#include <stdint.h>
#include "buffer.h"

/* INS_FALCON512_SIGN (0x43)
 * Multi-step signing protocol. P1 selects the sub-command:
 *   0x00 INIT, 0x06 FEED_MSG, 0x07 COMPUTE_HM,
 *   0x08 FEED_NONCE_HOST, 0x09 GEN_NONCE_DEVICE, 0x91 GET_NONCE,
 *   0x02 COMPUTE_TARGET, 0x03 FEED_TREE_STREAM,
 *   0x04 FEED_SWAP, 0x05 GET_SWAP, 0x90 GET_SIG.
 * See handler_falcon_sign.h for the documented v0.7.0 protocol; Falcon-512
 * uses the same protocol verbatim with smaller buffers. */
int handler_falcon512_sign(buffer_t *cdata, uint8_t p1, uint8_t p2);

#endif /* HANDLER_FALCON512_SIGN_H */
