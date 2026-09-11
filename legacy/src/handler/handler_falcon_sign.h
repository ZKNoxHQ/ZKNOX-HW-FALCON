#ifndef _HANDLER_FALCON_SIGN_H
#define _HANDLER_FALCON_SIGN_H
#include <stdint.h>
#include <stddef.h>
#include "buffer.h"
int handler_falcon_sign(buffer_t *cdata, uint8_t p1, uint8_t p2);
void *falcon_sign_get_tmp_buffer(size_t *out_size);
#endif
