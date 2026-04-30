#ifndef _HANDLER_FALCON_H
#define _HANDLER_FALCON_H
#include <stdint.h>
#include "buffer.h"
int handler_falcon_keygen(buffer_t *cdata);
int handler_falcon_get_pk(buffer_t *cdata, uint8_t p1, uint8_t p2);
#endif
