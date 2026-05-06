/*
 * handler_falcon512_flash.h — Falcon-512 flash variant — phase 2b (real sign)
 *
 * Phase 2b adds:
 *   - Real flash sign handler (INS 0x63 P1 = 0x00/0x06/0x08/0x09/0x10/0x91)
 *   - Real flash get_sig handler (INS 0x64 chunked)
 *
 * NVRAM layout unchanged from phase 2a:
 *   N_falcon_tree_512_storage[40960]   = L0 (4096) + R (18432) + L (18432)
 *   N_falcon_pk_512_storage[1024]      = persistent pk (h)
 *   N_falcon_tree_512_ready_storage[1] = ready flag
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "buffer.h"

int handler_falcon512_flash_keygen(buffer_t *cdata);
int handler_falcon512_flash_keygen_expand(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon512_flash_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon512_flash_sign(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon512_flash_get_sig(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon512_flash_dump_nvm(buffer_t *cdata, uint8_t p1, uint8_t p2);

#define FALCON_TREE_NVM_SIZE_512  40960
#define FALCON_PK_NVM_SIZE_512     1024

extern const uint8_t N_falcon_tree_512_storage[FALCON_TREE_NVM_SIZE_512];
extern const uint8_t N_falcon_pk_512_storage[FALCON_PK_NVM_SIZE_512];
extern const uint8_t N_falcon_tree_512_ready_storage;
