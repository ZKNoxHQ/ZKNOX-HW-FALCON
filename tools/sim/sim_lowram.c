/*
 * sim_lowram.c — drives the app's FALCON_CORE_* APDUs through apdu_dispatcher() on host.
 * Checks: keygen determinism (host reference), sign -> verify (legacy reference verify_raw),
 * persistence across a simulated restart, idempotent keygen, signature-norm statistics.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "os.h"
#include "buffer.h"
#include "globals.h"
#include "sw.h"
#include "dispatcher.h"
#include "falcon_lowram_nvm.h"

falcon_lr_storage_t g_falcon_lr;
global_ctx_t G_context;
const internal_storage_t N_storage_real = {0};
uint8_t g_resp[1024]; size_t g_resp_len; uint16_t g_resp_sw;
unsigned long g_nvm_write_calls, g_nvm_write_bytes;
int handler_get_version(void) { return io_send_sw(SWO_SUCCESS); }
int handler_get_app_name(void) { return io_send_sw(SWO_SUCCESS); }
int handler_get_public_key(buffer_t *b, bool d) { (void)b; (void)d; return io_send_sw(SWO_SUCCESS); }
int handler_sign_tx(buffer_t *b, uint8_t c, bool m, bool t) { (void)b;(void)c;(void)m;(void)t; return io_send_sw(SWO_SUCCESS); }
int handler_provide_token_info(buffer_t *b) { (void)b; return io_send_sw(SWO_SUCCESS); }
void *pic_shim(const void *p) { return (void *)p; }
int oracle_verify(unsigned logn, const uint16_t *h, const uint8_t *nonce, const uint8_t *msg, size_t msg_len, const int16_t *s2, uint32_t *sqn);

cx_err_t os_perso_derive_node_with_seed_key(unsigned mode, cx_curve_t curve, const uint32_t *path, unsigned pathlen,
        uint8_t *priv, uint8_t *chain, unsigned char *seed_key, unsigned seed_key_len) {
    (void)mode; (void)curve; (void)path; (void)pathlen;
    const char *fn = (seed_key_len == 16 && !memcmp(seed_key, "Falcon-1024 seed", 16)) ? "seed_1024.bin"
                   : (seed_key_len == 15 && !memcmp(seed_key, "Falcon-512 seed", 15))  ? "seed_512.bin" : NULL;
    if (!fn) { fprintf(stderr, "unknown seed_key\n"); exit(2); }
    FILE *f = fopen(fn, "rb"); if (!f || fread(priv, 1, 32, f) != 32) { perror(fn); exit(2); }
    fclose(f); memset(chain, 0, 32); return CX_OK;
}

static uint16_t apdu(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, uint8_t lc) {
    uint8_t d[256]; if (lc) memcpy(d, data, lc);
    command_t cmd = { CLA, ins, p1, p2, lc, lc ? d : NULL };
    g_resp_len = 0; g_resp_sw = 0; apdu_dispatcher(&cmd); return g_resp_sw;
}
static void need(uint16_t sw, const char *w) { if (sw != SWO_SUCCESS) { fprintf(stderr, "FAIL %s: sw=%04x\n", w, sw); exit(1); } }
static void pull(uint8_t ins, uint8_t logn, size_t total, uint8_t *out) {
    size_t off = 0; for (unsigned i = 0; off < total; i++) { need(apdu(ins, (uint8_t)i, logn, NULL, 0), "chunk"); memcpy(out + off, g_resp, g_resp_len); off += g_resp_len; }
}
static void sha256_hex(const uint8_t *p, size_t n, const char *label) {
    FILE *f = fopen("/tmp/_h.bin", "wb"); fwrite(p, 1, n, f); fclose(f);
    printf("  %-12s %5zu B  sha256 = ", label, n); fflush(stdout);
    system("python3 -c \"import hashlib;print(hashlib.sha256(open('/tmp/_h.bin','rb').read()).hexdigest())\"");
}
static int sign_once(uint8_t logn, const uint8_t *msg, const uint8_t *seed40, uint8_t *nonce, int16_t *s2, double *ms) {
    size_t n = (size_t)1 << logn;
    need(apdu(0x53, 0x00, logn, NULL, 0), "INIT"); need(apdu(0x53, 0x06, logn, msg, 32), "FEED_MSG");
    if (seed40) need(apdu(0x53, 0x08, logn, seed40, 40), "FEED_SEED"); else need(apdu(0x53, 0x09, logn, NULL, 0), "GEN_SEED");
    clock_t c0 = clock(); uint16_t sw = apdu(0x53, 0x10, logn, NULL, 0); if (ms) *ms = (double)(clock() - c0) * 1000.0 / CLOCKS_PER_SEC;
    if (sw != SWO_SUCCESS) return 0;
    need(apdu(0x53, 0x91, logn, NULL, 0), "GET_NONCE"); memcpy(nonce, g_resp, 40);
    pull(0x54, logn, 2 * n, (uint8_t *)s2); return 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int nstat = argc > 1 ? atoi(argv[1]) : 50;
    static uint8_t pk[2048], nonce[40], msg[32], seed40[40]; static int16_t s2[1024];
    for (int i = 0; i < 32; i++) msg[i] = (uint8_t)i; for (int i = 0; i < 40; i++) seed40[i] = (uint8_t)(0xA0 + i);
    for (uint8_t logn = 9; logn <= 10; logn++) {
        size_t n = (size_t)1 << logn;
        printf("== Falcon-%u low-RAM core (INS 0x50..0x54, P2 = %u)\n", 1u << logn, logn);
        g_nvm_write_calls = 0; clock_t c0 = clock();
        need(apdu(0x50, 0, logn, NULL, 0), "KEYGEN");
        printf("  KEYGEN: %.1f ms host, %lu nvm_write\n", (double)(clock() - c0) * 1000.0 / CLOCKS_PER_SEC, g_nvm_write_calls);
        pull(0x51, logn, 2 * n, pk); sha256_hex(pk, 2 * n, "pk (raw h)");
        { char ref[64]; snprintf(ref, 64, "ref_h%u.bin", 1u << logn); FILE *f = fopen(ref, "rb");
          if (f) { static uint8_t r[2048]; size_t rn = fread(r, 1, 2 * n, f); fclose(f); printf("  vs host low-RAM keygen (%s): %s\n", ref, (rn == 2 * n && !memcmp(r, pk, 2 * n)) ? "BYTE-MATCH" : "MISMATCH"); } }
        g_nvm_write_calls = 0; need(apdu(0x50, 0, logn, NULL, 0), "KEYGEN again"); printf("  KEYGEN again (same seed): %lu nvm_write (expected 0)\n", g_nvm_write_calls);
        double ms; uint32_t sqn;
        if (!sign_once(logn, msg, seed40, nonce, s2, &ms)) { printf("  SIGN failed\n"); return 1; }
        int ok = oracle_verify(logn, (uint16_t *)pk, nonce, msg, 32, s2, &sqn);
        printf("  SIGN_ALL (seeded): %.1f ms host; legacy verify_raw: %s, ||s||^2 = %u (bound %u)\n", ms, ok ? "VALID" : "INVALID", sqn, logn == 9 ? 34034726u : 70265242u);
        { char fn[64]; snprintf(fn, 64, "sig%u.bin", 1u << logn); FILE *f = fopen(fn, "wb"); fwrite(nonce, 1, 40, f); fwrite(s2, 2, n, f); fclose(f);
          snprintf(fn, 64, "pk%u.bin", 1u << logn); f = fopen(fn, "wb"); fwrite(pk, 1, 2 * n, f); fclose(f); fwrite(msg, 1, 32, f = fopen("msg32.bin", "wb")); fclose(f); }
        /* restart: BSS wiped, NVM kept -> SIGN without KEYGEN, same seed -> same signature */
        static int16_t s2b[1024]; static uint8_t nonceb[40];
        memset(&g_falcon_lr, 0, sizeof g_falcon_lr);
        if (!sign_once(logn, msg, seed40, nonceb, s2b, NULL)) { printf("  SIGN after restart failed\n"); return 1; }
        printf("  after restart, no KEYGEN: signature %s\n", (!memcmp(nonce, nonceb, 40) && !memcmp(s2, s2b, 2 * n)) ? "identical (deterministic seed)" : "DIFFERENT");
        /* stats with TRNG seeds */
        double sum = 0, sum2 = 0, tsum = 0; int rej = 0;
        for (int it = 0; it < nstat; it++) {
            uint8_t m[32]; for (int i = 0; i < 32; i++) m[i] = (uint8_t)(it * 7 + i * 13 + logn);
            if (!sign_once(logn, m, NULL, nonce, s2, &ms)) { rej++; continue; }
            tsum += ms; if (!oracle_verify(logn, (uint16_t *)pk, nonce, m, 32, s2, &sqn)) { printf("  INVALID signature in stats loop\n"); return 1; }
            sum += sqn; sum2 += (double)sqn * sqn;
        }
        int okn = nstat - rej; double mean = sum / okn, sigma = logn == 9 ? 165.7366171829776 : 168.38857144654395, exp_ = 2.0 * n * sigma * sigma;
        printf("  %d TRNG-seeded signatures: all verify, mean ||s||^2 / 2n*sigma^2 = %.4f, sd %.0f, %d failed, %.1f ms/sig host\n", okn, mean / exp_, sqrt(sum2 / okn - mean * mean), rej, tsum / okn);
    }
    printf("== BSS: sizeof(g_falcon_lr) = %zu B (area %d)\n", sizeof(falcon_lr_storage_t), FALCON_LR_AREA_SIZE);
    printf("== done\n");
    return 0;
}
