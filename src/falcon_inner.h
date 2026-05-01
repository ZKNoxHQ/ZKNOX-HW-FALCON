/*
 * falcon_inner.h — Wrapper for Falcon reference implementation
 *
 * Handles namespace conflicts with Dilithium:
 * - Undefs Dilithium poly_* macros before including Falcon inner.h
 * - Does NOT include falcon.h (SHAKE256 type conflict)
 */

#ifndef _FALCON_INNER_WRAPPER_H
#define _FALCON_INNER_WRAPPER_H

#ifndef FALCON_FPEMU
#define FALCON_FPEMU 1
#endif

/*
 * Dilithium's poly.h defines macros like:
 *   #define poly_sub pqcrystals_dilithium2_lowram_poly_sub
 * These corrupt Falcon's Zf(poly_sub) → Zf(pqcrystals_...) at link time.
 * Undef them before including Falcon's inner.h.
 * This is safe because Falcon handler files never call Dilithium poly functions.
 */
#undef poly_add
#undef poly_sub
#undef poly_reduce
#undef poly_caddq
#undef poly_shiftl
#undef poly_ntt
#undef poly_invntt_tomont
#undef poly_pointwise_montgomery
#undef poly_power2round
#undef poly_decompose
#undef poly_make_hint
#undef poly_use_hint
#undef poly_chknorm
#undef poly_uniform
#undef poly_uniform_eta
#undef poly_uniform_gamma1
#undef poly_challenge
#undef poly_challenge_eth
#undef polyvecl_uniform_eta
#undef polyvecl_uniform_gamma1
#undef polyvecl_reduce
#undef polyvecl_add
#undef polyvecl_ntt
#undef polyvecl_invntt_tomont
#undef polyvecl_pointwise_poly_montgomery
#undef polyvecl_chknorm
#undef polyveck_reduce
#undef polyveck_caddq
#undef polyveck_add
#undef polyveck_sub
#undef polyveck_shiftl
#undef polyveck_ntt
#undef polyveck_invntt_tomont
#undef polyveck_decompose
#undef polyveck_make_hint
#undef polyveck_pack_w1
#undef polyz_pack
#undef polyz_unpack
#undef polyw1_pack
#undef polyt1_pack
#undef polyt1_unpack
#undef polyt0_pack
#undef polyt0_unpack
#undef polyeta_pack
#undef polyeta_unpack

/* Now safe to include Falcon inner API */
#include "zknox/falcon/inner.h"

/* Clean aliases */
#define falcon_keygen              Zf(keygen)
#define falcon_to_ntt_monty        Zf(to_ntt_monty)
#define falcon_verify_raw          Zf(verify_raw)
#define falcon_complete_private    Zf(complete_private)
#define falcon512_hash_to_point    Zf(hash_to_point_vartime)

#endif /* _FALCON_INNER_WRAPPER_H */
