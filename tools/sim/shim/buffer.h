#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef struct { const uint8_t *ptr; size_t size; size_t offset; } buffer_t;
