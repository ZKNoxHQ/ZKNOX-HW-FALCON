/* Host-side BOLOS shim for wire simulation */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Opaque relocation like the device's PIC(): keeps the compiler from folding
 * reads of const NVM objects to their initializers. Defined in opcount.c. */
void *pic_shim(const void *p);
#define PIC(x) pic_shim((const void *)(x))
#define WEAK

typedef int cx_err_t;
#define CX_OK 0
typedef enum { CX_CURVE_Ed25519 = 0x21 } cx_curve_t;
#define HDW_ED25519_SLIP10 2

/* --- simulated NVM: flat memcpy + accounting --- */
extern unsigned long g_nvm_write_calls, g_nvm_write_bytes;
#include <sys/mman.h>
#include <unistd.h>
/* Device: N_* storage lives in flash and nvm_write goes through the OS.
 * Host: the const arrays land in .rodata, so unprotect the pages first. */
static inline void nvm_write(void *dst, void *src, unsigned int n) {
    uintptr_t pg = (uintptr_t)sysconf(_SC_PAGESIZE);
    uintptr_t a = (uintptr_t)dst & ~(pg - 1), e = ((uintptr_t)dst + n + pg - 1) & ~(pg - 1);
    mprotect((void *)a, e - a, PROT_READ | PROT_WRITE);
    memmove(dst, src, n);
    g_nvm_write_calls++; g_nvm_write_bytes += n;
}

/* --- APDU response capture --- */
extern uint8_t  g_resp[1024]; extern size_t g_resp_len; extern uint16_t g_resp_sw;
static inline int io_send_sw(uint16_t sw) { g_resp_len = 0; g_resp_sw = sw; return 0; }
static inline int io_send_response_pointer(const uint8_t *p, size_t n, uint16_t sw) {
    if (n > sizeof g_resp) n = sizeof g_resp;
    memcpy(g_resp, p, n); g_resp_len = n; g_resp_sw = sw; return 0;
}

/* --- deterministic "TRNG" for reproducible runs --- */
static inline void cx_rng_no_throw(uint8_t *b, size_t n) {
    static uint32_t s = 0x12345678u;
    for (size_t i = 0; i < n; i++) { s = s * 1664525u + 1013904223u; b[i] = (uint8_t)(s >> 24); }
}

/* Seed derivation: host precomputes SLIP-10 leaf (Python), shim returns it. */
cx_err_t os_perso_derive_node_with_seed_key(unsigned mode, cx_curve_t curve,
        const uint32_t *path, unsigned pathlen, uint8_t *priv, uint8_t *chain,
        unsigned char *seed_key, unsigned seed_key_len);

#ifndef explicit_bzero
#define explicit_bzero(p, n) memset((p), 0, (n))
#endif
