/*
 * falcon_sampler_protect.h — SCA-protected SamplerZ (Lin et al. PKC 2025)
 *
 * Algorithms 5, 6, 7 from
 *   Lin, Zhang, Yu, Wang, You, Xu, Wang.
 *   "Thorough Power Analysis on Falcon Gaussian Samplers and Practical
 *    Countermeasure". PKC 2025.
 *   ePrint: https://eprint.iacr.org/2025/351
 *
 * Drop-in replacement for Zf(sampler) with SCA-protected power consumption
 * profile. Same signature, same semantics, different sampling-time PRNG
 * tape consumption (so sigs are NOT byte-identical to Zf(sampler) sigs;
 * both are valid under verify_raw).
 *
 * Workspace is provided by the caller via g_falcon_sampler_protect_ws.
 * The pointer MUST be set to a valid falcon_sampler_protect_ws_t buffer
 * before invoking sampler_protect. The buffer can live anywhere in RAM —
 * typically aliased onto the existing _falcon_sign_area (no extra BSS).
 */
#pragma once

#include "falcon_inner.h"

/* Workspace required by sampler_protect (~1.2 KB).
 * Placed by the caller; not allocated in this module's BSS. */
typedef struct {
    fpr      x_arr[3][19];          /* 456 B — Algorithm 6 line 16-19 */
    fpr      r_array[3][19];        /* 456 B — BerExp internal r */
    uint64_t z_array_local[2][19];  /* 304 B — BerExp internal z */
} falcon_sampler_protect_ws_t;

extern falcon_sampler_protect_ws_t *g_falcon_sampler_protect_ws;

int sampler_protect(void *ctx, fpr mu, fpr isigma);
