#pragma once
#include <stdint.h>
#include "buffer.h"

/* Same APDU contract as handler_falcon512_flash_sign (INS 0x63), but routes
 * through the SCA-protected sampler. The signature output lands in the
 * SAME memory location (fctx.hm_sig.sig in _falcon_sign_area), so the
 * existing GET_SIG (INS 0x64) reads it back regardless of which SIGN
 * variant produced it. */
int handler_falcon512_flash_sign_protect(buffer_t *cdata, uint8_t p1, uint8_t p2);
