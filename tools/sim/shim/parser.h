#pragma once
#include <stdint.h>
typedef struct { uint8_t cla, ins, p1, p2, lc; uint8_t *data; } command_t;
