#ifndef _HANDLER_FALCON_KEYGEN_EXPAND_H
#define _HANDLER_FALCON_KEYGEN_EXPAND_H
#include <stdint.h>
#include "buffer.h"

/*
 * Falcon-1024 streaming keygen-expand.
 *
 * Consumes g_zknox.falcon_{seed,f,g,F,G} (populated by a prior
 * FALCON_KEYGEN) and streams out a v0.4.0 wire blob (122864 B total)
 * that the sign handler's FEED_SWAP + FEED_TREE_STREAM can consume.
 *
 * Sub-phases (P1):
 *   0x00 COMPUTE_L0      — run Gram + Level-10 LDL, stage L0
 *   0x01 GET_L0 P2=idx   — pull 255 B chunk at offset idx*255 (total 8208 B)
 *   0x02 PREP_RIGHT      — splits + right-walker init
 *   0x03 GET_NEXT_R      — pull next chunk of right subtree (<=255 B)
 *   0x04 PREP_LEFT       — swap walker to left subtree
 *   0x05 GET_NEXT_L      — pull next chunk of left subtree (<=255 B)
 *
 * Wire layout:
 *   0      L0 ct     (8192 B)
 *   8192   L0 tag    (16 B)
 *   8208   right subtree records (57328 B)
 *   65536  left  subtree records (57328 B)
 *  122864  total
 *
 * NOTE: this operation DESTROYS any pk chunks previously staged in
 * _falcon_sign_area. The host must pull the public key via
 * FALCON_GET_PK BEFORE calling this handler.
 */
int handler_falcon_keygen_expand(buffer_t *cdata, uint8_t p1, uint8_t p2);

#endif
