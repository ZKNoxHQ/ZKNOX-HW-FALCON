/*
 * handler_falcon1024_flash.h — Falcon-1024 flash variant
 *
 * NVRAM layout (109 569 bytes total):
 *   N_falcon_tree_1024_storage[90112]      = L0 (8192) + R (40960) + L (40960)
 *   N_falcon_pk_1024_storage[2048]         = persistent pk (h)
 *   N_falcon_G_1024_storage[1024]          = persistent G (computed during keygen,
 *                                            reused in expand/sign — avoids
 *                                            stack-heavy complete_private calls
 *                                            that overflow the BOLOS app stack)
 *   N_falcon_zscratch_1024_storage[16384]  = z0 + z1 scratch during sign
 *                                            (BSS too tight for z_pair_save in
 *                                             Falcon-1024)
 *   N_falcon_tree_1024_ready_storage[1]    = ready flag
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "buffer.h"

int handler_falcon1024_flash_keygen(buffer_t *cdata);
int handler_falcon1024_flash_keygen_expand(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon1024_flash_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon1024_flash_sign(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon1024_flash_get_sig(buffer_t *cdata, uint8_t p1, uint8_t p2);
int handler_falcon1024_flash_dump_nvm(buffer_t *cdata, uint8_t p1, uint8_t p2);

#define FALCON_TREE_NVM_SIZE_1024     90112
#define FALCON_PK_NVM_SIZE_1024        2048
#define FALCON_G_NVM_SIZE_1024         1024
#define FALCON_ZSCRATCH_NVM_SIZE_1024 16384

extern const uint8_t N_falcon_tree_1024_storage[FALCON_TREE_NVM_SIZE_1024];
extern const uint8_t N_falcon_pk_1024_storage[FALCON_PK_NVM_SIZE_1024];
extern const uint8_t N_falcon_G_1024_storage[FALCON_G_NVM_SIZE_1024];
extern const uint8_t N_falcon_zscratch_1024_storage[FALCON_ZSCRATCH_NVM_SIZE_1024];
extern const uint8_t N_falcon_tree_1024_ready_storage;
