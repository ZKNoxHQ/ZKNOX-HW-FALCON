/*
 * falcon_sampler_protect.c — Algorithms 5/6/7 from Lin et al. PKC 2025
 *
 * The 1.2 KB of workspaces (x_arr, r_array, z_array_local) are NOT in this
 * module's BSS — caller provides them via g_falcon_sampler_protect_ws. This
 * lets the caller alias the workspaces onto an existing memory region (the
 * Falcon-512 flash sign handler aliases them inside _falcon_sign_area,
 * which has ~8 KB of headroom after fctx). Net BSS increase: 0.
 *
 * Single-threaded (BOLOS apps are). Caller MUST set the pointer before
 * invoking sampler_protect.
 */

#include <stdint.h>
#include <stddef.h>
#include "falcon_inner.h"
#include "falcon_sampler_protect.h"

falcon_sampler_protect_ws_t *g_falcon_sampler_protect_ws;

#define WS  (*g_falcon_sampler_protect_ws)

/* ===================================================================== *
 * Constants (.rodata — does not contribute to BSS)
 * ===================================================================== */
static const fpr z0_sqr_inv_2sqrsigma0[19] = {
    0,
    4594603506513722306ULL, 4603610705768463298ULL, 4608793741173732154ULL,
    4612617905023204290ULL, 4615675366023746911ULL, 4617800940428473146ULL,
    4620009106706642817ULL, 4621625104277945282ULL, 4623068905305979298ULL,
    4624682565278487903ULL, 4625831450752485245ULL, 4626808139683214138ULL,
    4627869758086180326ULL, 4629016305961383809ULL, 4629974100122847238ULL,
    4630632303532686274ULL, 4631332971678643958ULL, 4632076104560720290ULL
};

static const fpr z0_fpr[19] = {
    0,
    4607182418800017408ULL, 4611686018427387904ULL, 4613937818241073152ULL,
    4616189618054758400ULL, 4617315517961601024ULL, 4618441417868443648ULL,
    4619567317775286272ULL, 4620693217682128896ULL, 4621256167635550208ULL,
    4621819117588971520ULL, 4622382067542392832ULL, 4622945017495814144ULL,
    4623507967449235456ULL, 4624070917402656768ULL, 4624633867356078080ULL,
    4625196817309499392ULL, 4625478292286210048ULL, 4625759767262920704ULL
};

static const int b_table_protect[16] = {
    2, 1, 1, 2, 2, 1, 1, 2,
    2, 1, 1, 2, 2, 1, 1, 2
};

/* ===================================================================== *
 * Algorithm 5 — protected gaussian0_sampler
 * ===================================================================== */
static void gaussian0_sampler_protect(int *z_array, prng *p)
{
    static const uint32_t dist[] = {
        10745844u,  3068844u,  3741698u,
         5559083u,  1580863u,  8248194u,
         2260429u, 13669192u,  2736639u,
          708981u,  4421575u, 10046180u,
          169348u,  7122675u,  4136815u,
           30538u, 13063405u,  7650655u,
            4132u, 14505003u,  7826148u,
             417u, 16768101u, 11363290u,
              31u,  8444042u,  8086568u,
               1u, 12844466u,   265321u,
               0u,  1232676u, 13644283u,
               0u,    38047u,  9111839u,
               0u,      870u,  6138264u,
               0u,       14u, 12545723u,
               0u,        0u,  3104126u,
               0u,        0u,    28824u,
               0u,        0u,      198u,
               0u,        0u,        1u
    };

    uint32_t v0, v1, v2, hi;
    uint64_t lo;
    size_t u;

    lo = prng_get_u64(p);
    hi = prng_get_u8(p);
    v0 = (uint32_t)lo & 0xFFFFFFu;
    v1 = (uint32_t)(lo >> 24) & 0xFFFFFFu;
    v2 = (uint32_t)(lo >> 48) | (hi << 16);

    for (u = 0; u < (sizeof dist) / sizeof(dist[0]); u += 3) {
        uint32_t w0, w1, w2, cc;
        uint32_t bb = 0x1FFFFFFu;

        w0 = dist[u + 2];
        w1 = dist[u + 1];
        w2 = dist[u + 0];
        cc = (v0 - w0) >> 31;
        cc = (v1 - w1 - cc) >> 31;
        z_array[u/3] = (int)(((bb - v2 + w2 + cc) >> 24) & 0x3);
    }
}

/* ===================================================================== *
 * Algorithm 6 helper — precompute x[b'][z+] (writes WS.x_arr)
 * ===================================================================== */
static void compute_x_protect(fpr c_bar[3], fpr dsss)
{
    for (int b_i = 1; b_i < 3; b_i++) {
        for (int j = 0; j < 19; j++) {
            WS.x_arr[b_i][j] = fpr_sub(
                fpr_mul(
                    fpr_sqr(fpr_add(z0_fpr[j], c_bar[b_i])),
                    dsss),
                z0_sqr_inv_2sqrsigma0[j]);
        }
    }
}

/* ===================================================================== *
 * Algorithm 7 — protected BerExp
 * ===================================================================== */
static int BerExp_protect(prng *p, fpr ccs, int *z0_array,
                          int z0_index, int s_in, int b_in)
{
    int i;
    uint32_t sw, w;
    int s_array[3][19];
    uint64_t z_prime;

    for (int b_i = 1; b_i < 3; b_i++) {
        for (int j = 0; j < 19; j++) {
            s_array[b_i][j] = (int)fpr_trunc(
                fpr_mul(WS.x_arr[b_i][j], fpr_inv_log2));
            WS.r_array[b_i][j] = fpr_sub(WS.x_arr[b_i][j],
                fpr_mul(fpr_of(s_array[b_i][j]), fpr_log2));
            sw = (uint32_t)s_array[b_i][j];
            sw ^= (sw ^ 63) & -((63 - sw) >> 31);
            s_array[b_i][j] = (int)sw;
            WS.z_array_local[b_i - 1][j] =
                ((fpr_expm_p63(WS.r_array[b_i][j], ccs) << 1) - 1)
                >> s_array[b_i][j];
        }
    }

    z_prime = WS.z_array_local[b_in >> 1][z0_array[z0_index] - s_in];

    i = 64;
    do {
        i -= 8;
        w = prng_get_u8(p) - ((uint32_t)(z_prime >> i) & 0xFFu);
    } while (!w && i > 0);
    return (int)(w >> 31);
}

/* ===================================================================== *
 * Algorithm 6 — protected SamplerZ (entry point)
 * ===================================================================== */
int sampler_protect(void *ctx, fpr mu, fpr isigma)
{
    sampler_context *spc;
    int s;
    fpr r, dss, ccs;
    fpr c_bar[3];

    spc = (sampler_context *)ctx;

    s = (int)fpr_floor(mu);
    r = fpr_sub(mu, fpr_of(s));

    c_bar[0] = 0;
    c_bar[1] = r;
    c_bar[2] = fpr_sub(fpr_of(1), r);

    dss = fpr_half(fpr_sqr(isigma));
    ccs = fpr_mul(isigma, spc->sigma_min);

    for (;;) {
        int b, b_idx, z0_idx;
        int z00_arr[18], z01_arr[18], z02_arr[18], z03_arr[18];
        int z0_arr[4];
        int z_arr[3][19];
        int z00_temp, z01_temp, z02_temp, z03_temp;

        b_idx = (int)prng_get_u8(&spc->p) & 0xF;
        b = b_table_protect[b_idx];

        gaussian0_sampler_protect(z00_arr, &spc->p);
        gaussian0_sampler_protect(z01_arr, &spc->p);
        gaussian0_sampler_protect(z02_arr, &spc->p);
        gaussian0_sampler_protect(z03_arr, &spc->p);

        z00_temp = s
            + (z00_arr[17] & 1) + (z00_arr[16] & 1) + (z00_arr[15] & 1)
            + (z00_arr[14] & 1) + (z00_arr[13] & 1) + (z00_arr[12] & 1)
            + (z00_arr[11] & 1) + (z00_arr[10] & 1) + (z00_arr[ 9] & 1)
            + (z00_arr[ 8] & 1) + (z00_arr[ 7] & 1) + (z00_arr[ 6] & 1)
            + (z00_arr[ 5] & 1) + (z00_arr[ 4] & 1) + (z00_arr[ 3] & 1)
            + (z00_arr[ 2] & 1) + (z00_arr[ 1] & 1) + (z00_arr[ 0] & 1);
        z0_arr[0] = 18 + 2 * s - z00_temp;

        z01_temp = s
            + (z01_arr[17] & 1) + (z01_arr[16] & 1) + (z01_arr[15] & 1)
            + (z01_arr[14] & 1) + (z01_arr[13] & 1) + (z01_arr[12] & 1)
            + (z01_arr[11] & 1) + (z01_arr[10] & 1) + (z01_arr[ 9] & 1)
            + (z01_arr[ 8] & 1) + (z01_arr[ 7] & 1) + (z01_arr[ 6] & 1)
            + (z01_arr[ 5] & 1) + (z01_arr[ 4] & 1) + (z01_arr[ 3] & 1)
            + (z01_arr[ 2] & 1) + (z01_arr[ 1] & 1) + (z01_arr[ 0] & 1);
        z0_arr[1] = 18 + 2 * s - z01_temp;

        z02_temp = s
            + (z02_arr[17] & 1) + (z02_arr[16] & 1) + (z02_arr[15] & 1)
            + (z02_arr[14] & 1) + (z02_arr[13] & 1) + (z02_arr[12] & 1)
            + (z02_arr[11] & 1) + (z02_arr[10] & 1) + (z02_arr[ 9] & 1)
            + (z02_arr[ 8] & 1) + (z02_arr[ 7] & 1) + (z02_arr[ 6] & 1)
            + (z02_arr[ 5] & 1) + (z02_arr[ 4] & 1) + (z02_arr[ 3] & 1)
            + (z02_arr[ 2] & 1) + (z02_arr[ 1] & 1) + (z02_arr[ 0] & 1);
        z0_arr[2] = 18 + 2 * s - z02_temp;

        z03_temp = s
            + (z03_arr[17] & 1) + (z03_arr[16] & 1) + (z03_arr[15] & 1)
            + (z03_arr[14] & 1) + (z03_arr[13] & 1) + (z03_arr[12] & 1)
            + (z03_arr[11] & 1) + (z03_arr[10] & 1) + (z03_arr[ 9] & 1)
            + (z03_arr[ 8] & 1) + (z03_arr[ 7] & 1) + (z03_arr[ 6] & 1)
            + (z03_arr[ 5] & 1) + (z03_arr[ 4] & 1) + (z03_arr[ 3] & 1)
            + (z03_arr[ 2] & 1) + (z03_arr[ 1] & 1) + (z03_arr[ 0] & 1);
        z0_arr[3] = 18 + 2 * s - z03_temp;

        z0_idx = (int)prng_get_u8(&spc->p) & 0x3;

        for (int j = 0; j < 19; j++) {
            z_arr[1][j] = s - j;
            z_arr[2][j] = 1 + s + j;
        }

        compute_x_protect(c_bar, dss);

        if (BerExp_protect(&spc->p, ccs, z0_arr, z0_idx, s, b)) {
            return z_arr[b][z0_arr[z0_idx] - s];
        }
    }
}
