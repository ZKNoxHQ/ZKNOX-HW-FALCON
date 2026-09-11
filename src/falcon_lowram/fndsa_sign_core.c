/*
 * Core signature generation.
 */

#include "fndsa_sign_inner.h"

/* Private key access: FN-DSA keys pack f and g (nbits per coefficient),
   Falcon mode (FNDSA_FALCON_R3) receives them raw (int8, n bytes each). */
#if FNDSA_FALCON_R3
#define KEY_DECODE(logn, src, dst, nbits) \
	memcpy((dst), (src), (size_t)1 << (logn))
#else
#define KEY_DECODE(logn, src, dst, nbits) \
	((void)trim_i8_decode((logn), (src), (dst), (nbits)))
#endif

/* see sign_inner.h */
TARGET_SSE2 TARGET_NEON
size_t
sign_core(unsigned logn,
	const uint8_t *sign_key_fgF, const uint8_t *mu, size_t mu_len,
	const uint8_t *seed, size_t seed_len, uint8_t *sig, void *tmp)
{
	/* Output value is 0 on error, or the signature length on success. */
	size_t ret = 0;

#if FNDSA_SSE2
	/* We must ensure that the rounding mode is appropriate (we need
	   the roundTiesToEven policy, which is normally the default, but
	   could have been changed by the calling application. */
	unsigned round_mode = _MM_GET_ROUNDING_MODE();
	_MM_SET_ROUNDING_MODE(_MM_ROUND_NEAREST);
#endif
	/* Note: on aarch64, we use only NEON intrinsics, and NEON always
	   uses "round to nearest" mode, which is the IEEE-754
	   roundTiesToEven (NEON also always flushes denormals to zero,
	   which is not IEEE-754 compliant, but we do not care because
	   we never get any denormal value anywhere in signature
	   generation). */

	size_t n = (size_t)1 << logn;
	unsigned nbits = fg_nbits(logn);

	/* Storage format of F is already an array of int8_t.
	   Note: we do not check that all coefficients of F[] are in
	   [-127, +127]: the private key is assumed to be correct, and
	   our API contract does not involve checking it. It is not actually
	   a problem if a coefficient of F happens to be equal to -128;
	   at worst, an invalid private key may lead to repeated failure
	   to sign, which will exit after 27 attempts. */
#if FNDSA_FALCON_R3
	/* Raw private key: f | g | F, int8, n bytes each. */
	(void)nbits;
	size_t flen = n;
#else
	size_t flen = (nbits << logn) >> 3;
#endif
	int8_t *F = (int8_t *)(sign_key_fgF + (flen << 1));

	/* We will use the output buffer (sig[]) to store some values:
	    - The nonce (40 bytes) goes directly into sig + 1. This is
	      where it will appear in the final signature anyway.
	    - When computing f*adj(f) + g*adj(g), the value is obtained
	      modulo q', then adjusted by recomputing it modulo q. Whether
	      an adjustment to any individual value was needed is stored
	      in a bitfield, that starts at sig + 41. These bits allow
	      recomputing f*adj(f) + g*adj(g) later on by working only
	      modulo q'. The signature buffer is always large enough for
	      that bitfield. */

	/* The loop contents usually run one time; restart probability
	   is about 1/2450 at n=512, 1/820 at n=1024. Thus, probability
	   of needing more than 27 iterations is less than 2^(-256).
	   We force an exit after 27 iterations; repeated failures are
	   conceptually feasible if the private key has invalid contents. */
	for (uint8_t counter = 0; counter < 27; counter ++) {
		/* Initialize a SHAKE context which will be used throughout
		   for getting the 40-byte nonce, then the sampling.
		   The nonce is stored directly in the signature output
		   buffer (sig + 1). */
		sampler_state ss;
		ss.logn = logn;
		shake_init(&ss.pc, 256);
		shake_inject(&ss.pc, seed, seed_len);
		shake_inject(&ss.pc, &counter, 1);
		shake_flip(&ss.pc);
		shake_extract(&ss.pc, sig + 1, 40);

		uint16_t *tmp0 = (uint16_t *)tmp;
		uint16_t *tmp2 = tmp0 + n;
		uint16_t *tmp4 = tmp0 + 2 * n;
		uint16_t *tmp6 = tmp0 + 3 * n;
		uint16_t *tmp8 = tmp0 + 4 * n;
		uint16_t *tmp10 = tmp0 + 5 * n;
		uint16_t *tmp12 = tmp0 + 6 * n;
		uint16_t *tmp14 = tmp0 + 7 * n;
		uint16_t *tmp16 = tmp0 + 8 * n;
		uint16_t *tmp18 = tmp0 + 9 * n;

		/* Step 1
		   Compute q^2/(f*adj(f) + g*adj(g)) (FFT) and
		   c*f mod q (normalized) */

		/* tmp4  <- f  (n bytes, into first half of tmp4) */
		KEY_DECODE(logn, sign_key_fgF, (int8_t *)tmp4, nbits);

		uint32_t sqnf = mqpoly_sqnorm_small(logn, (int8_t *)tmp4);

		/* tmp0  <- f mod q'  (NTT mod q') */
		mq2poly_small_to_mod(logn, (int8_t *)tmp4, tmp0);
		mq2poly_NTT(logn, tmp0);

		/* tmp4  <- g  (n bytes, into second half of tmp4) */
		KEY_DECODE(logn, sign_key_fgF + flen, (int8_t *)tmp4 + n, nbits);

		uint32_t sqng = mqpoly_sqnorm_small(logn, (int8_t *)tmp4 + n);

		/* If ||(g,-f)|| > 1.17*sqrt(q) then the private key is
		   invalid, and that could lead us to incorrect computations
		   for f*adj(f) + g*adj(g), which could conceptually lead
		   to a quasi-infinite loop in SamplerZ. We avoid this issue
		   by checking the norm here. */
		if (sqnf + sqng > 16822) {
			return 0;
		}

		/* tmp2  <- g mod q'  (NTT mod q') */
		mq2poly_small_to_mod(logn, (int8_t *)tmp4 + n, tmp2);
		mq2poly_NTT(logn, tmp2);

		/* tmp0  <- f*adj(f) + g*adj(g) mod q' (normalized) */
		mq2poly_muladj_x2_ntt(logn, tmp0, tmp2);
		mq2poly_iNTT(logn, tmp0);
		mq2poly_mod_to_signed(logn, tmp0);

		/* tmp18 <- f mod q  (NTT mod q) */
		mqpoly_small_to_int(logn, (int8_t *)tmp4, tmp18);
		mqpoly_int_to_ntt(logn, tmp18);

		/* tmp2  <- g mod q  (NTT mod q) */
		mqpoly_small_to_int(logn, (int8_t *)tmp4 + n, tmp2);
		mqpoly_int_to_ntt(logn, tmp2);

		/* tmp2  <- f*adj(f) + g*adj(g) mod q (normalized) */
		mqpoly_muladj_x2_ntt(logn, tmp2, tmp18);
		mqpoly_ntt_to_int(logn, tmp2);
		mqpoly_int_to_signed(logn, tmp2);

		/* tmp0 and tmp2 contain f*adj(f) + g*adj(g) mod q' and
		   mod q, respectively (both normalized). We adjust the
		   value in tmp0 so that it matches the value in tmp2.
		   The adjustment bits are saved in sig + 41. */
		mq2mqpoly_adjust_save(logn - 1,
			(int16_t *)tmp0, (int16_t *)tmp2, sig + 41);

		/* tmp8  <- q^2/(f*adj(f) + g*adj(g))  (FFT, self-adj) */
		fpoly_FFT_int16_selfadj(logn, (fpr *)tmp8, (int16_t *)tmp0);
		fpoly_invmul_selfadj_fft(logn, (fpr *)tmp8, FPR_QQ);

		/* tmp16 <- c*f mod q  (normalized) */
		hash_to_point(logn, sig + 1, mu, mu_len, tmp16);
		mqpoly_ext_to_int(logn, tmp16);
		mqpoly_int_to_ntt(logn, tmp16);
		mqpoly_mul_ntt(logn, tmp16, tmp18);
		mqpoly_ntt_to_int(logn, tmp16);
		mqpoly_int_to_signed(logn, tmp16);

		/* Step 2
		   ffSampling on t1 */
		ss.dz = (int16_t *)tmp16;
		ffsamp_fft(&ss, FLAG_INIT0, tmp);

		/* Step 3
		   We have t1 - z1 (FFT) in tmp0. */

		/* tmp12 <- f mod q  (NTT mod q)
		   Value is already in tmp18. */
		memcpy(tmp12, tmp18, n * sizeof(uint16_t));

		/* tmp18 <- 1/f mod q  (NTT mod q) */
		mqpoly_inv_ntt(logn, tmp18, tmp10);

		/* tmp14 <- g mod q  (NTT mod q) */
		KEY_DECODE(logn, sign_key_fgF + flen, (int8_t *)tmp10, nbits);
		mqpoly_small_to_int(logn, (int8_t *)tmp10, tmp14);
		mqpoly_int_to_ntt(logn, tmp14);

		/* tmp8  <- F mod q  (NTT mod q) */
		mqpoly_small_to_int(logn, F, tmp8);
		mqpoly_int_to_ntt(logn, tmp8);

		/* tmp10 <- G = (q + g*F)/f mod q  (NTT mod q) */
		memcpy(tmp10, tmp14, n * sizeof(uint16_t));
		mqpoly_mul_ntt(logn, tmp10, tmp8);
		mqpoly_mul_ntt(logn, tmp10, tmp18);

		/* tmp8  <- F*adj(f) + G*adj(g) mod q  (normalized) */
		mqpoly_muladj_add_muladj(logn, tmp8, tmp12, tmp10, tmp14);
		mqpoly_ntt_to_int(logn, tmp8);
		mqpoly_int_to_signed(logn, tmp8);

		/* tmp10 <- G  (normalized) */
		mqpoly_ntt_to_int(logn, tmp10);
		mqpoly_int_to_signed(logn, tmp10);

		/* tmp10 <- G mod q'  (NTT mod q') */
		mq2poly_signed_to_mod(logn, tmp10);
		mq2poly_NTT(logn, tmp10);

		/* tmp14 <- g mod q'  (NTT mod q') */
		KEY_DECODE(logn, sign_key_fgF + flen, (int8_t *)tmp18, nbits);
		mq2poly_small_to_mod(logn, (int8_t *)tmp18, tmp14);
		mq2poly_NTT(logn, tmp14);

		/* tmp10 <- G*adj(g) mod q'  (NTT mod q') */
		mq2poly_muladj_ntt(logn, tmp10, tmp14);

		/* tmp12 <- f mod q'  (NTT mod q') */
		KEY_DECODE(logn, sign_key_fgF, (int8_t *)tmp18, nbits);
		mq2poly_small_to_mod(logn, (int8_t *)tmp18, tmp12);
		mq2poly_NTT(logn, tmp12);

		/* tmp18 <- f*adj(f) + g*adj(g) mod q'  (normalized) */
		memcpy(tmp18, tmp12, n * sizeof(uint16_t));
		mq2poly_muladj_x2_ntt(logn, tmp18, tmp14);
		mq2poly_iNTT(logn, tmp18);
		mq2poly_mod_to_signed(logn, tmp18);

		/* Adjust value in tmp18 to contain the true value of
		   f*adj(f) + g*adj(g). We reuse the adjustment bits
		   that were previously saved in sig + 41. */
		mq2mqpoly_adjust(logn - 1, (int16_t *)tmp18, sig + 41);

		/* tmp14 <- F mod q'  (NTT mod q') */
		mq2poly_small_to_mod(logn, F, tmp14);
		mq2poly_NTT(logn, tmp14);

		/* tmp10 <- F*adj(f) + G*adj(g) mod q'  (normalized) */
		mq2poly_muladj_ntt(logn, tmp14, tmp12);
		mq2poly_add(logn, tmp10, tmp14);
		mq2poly_iNTT(logn, tmp10);
		mq2poly_mod_to_signed(logn, tmp10);

		/* tmp12 <- F*adj(f) + G*adj(g)  (int32) */
		mq2mqpoly_CRT(logn, (int32_t *)tmp12,
			(int16_t *)tmp8, (int16_t *)tmp10);

		/* tmp8  <- F*adj(f) + G*adj(g)  (FFT) */
		fpoly_FFT_int32(logn, (fpr *)tmp8, (int32_t *)tmp12);

		/* tmp0  <- (t1 - z1)*(F*adj(f) + G*adj(g))  (FFT) */
		fpoly_mul_fft(logn, (fpr *)tmp0, (fpr *)tmp8);

		/* tmp8  <- f*adj(f) + g*adj(g)  (FFT, self-adj) */
		fpoly_FFT_int16_selfadj(logn, (fpr *)tmp8, (int16_t *)tmp18);

		/* tmp0  <- tmp0 / tmp8  (FFT) */
		fpoly_div_selfadj_fft(logn, (fpr *)tmp0, (fpr *)tmp8);

		/* tmp12 <- c  (NTT mod q) */
		hash_to_point(logn, sig + 1, mu, mu_len, tmp12);
		mqpoly_ext_to_int(logn, tmp12);
		mqpoly_int_to_ntt(logn, tmp12);

		/* tmp18 <- -F  (NTT mod q) */
		mqpoly_small_to_int(logn, F, tmp18);
		mqpoly_int_to_ntt(logn, tmp18);
		mqpoly_neg(logn, tmp18);

		/* tmp18 <- -c*F mod q  (normalized) */
		mqpoly_mul_ntt(logn, tmp18, tmp12);
		mqpoly_ntt_to_int(logn, tmp18);
		mqpoly_int_to_signed(logn, tmp18);

		/* Step 4
		   ffSampling on t0' */
		ss.dz = (int16_t *)tmp18;
		ffsamp_fft(&ss, FLAG_NOOUT, tmp);

		/* Step 5
		   Build signature: s1 = f*(z0 + r0) + F*(z1 + r1)
		   with:
		      c*f = (c*f mod q) + q*r1
		      -c*F = (-c*F mod q) + q*r0
		   This simplifies to:
		      s1 = f*(z0 + (-c*F)/q - (-c*F mod q)/q)
		         + F*(z1 + c*f/q - (c*f mod q)/q)
		      s1 = f*(z0 + (c*F mod q)/q) + F*(z1 - (c*f mod q)/q)
		   Since s1 is integral, we can do these computations
		   modulo q'.
		   We obtained z0 and z1 in tmp18 and tmp16, respectively. */

		/* tmp2  <- c mod q  (NTT mod q) */
		hash_to_point(logn, sig + 1, mu, mu_len, tmp2);
		mqpoly_ext_to_int(logn, tmp2);
		mqpoly_int_to_ntt(logn, tmp2);

		/* tmp4  <- f mod q  (NTT mod q)
		   (f[] into tmp12) */
		KEY_DECODE(logn, sign_key_fgF, (int8_t *)tmp12, nbits);

		mqpoly_small_to_int(logn, (int8_t *)tmp12, tmp4);
		mqpoly_int_to_ntt(logn, tmp4);

		/* tmp6  <- F mod q  (NTT mod q) */
		mqpoly_small_to_int(logn, F, tmp6);
		mqpoly_int_to_ntt(logn, tmp6);

		/* tmp8  <- c*f mod q  (normalized) */
		memcpy(tmp8, tmp2, n * sizeof(uint16_t));
		mqpoly_mul_ntt(logn, tmp8, tmp4);
		mqpoly_ntt_to_int(logn, tmp8);
		mqpoly_int_to_signed(logn, tmp8);

		/* tmp6  <- c*F mod q  (normalized) */
		mqpoly_mul_ntt(logn, tmp6, tmp2);
		mqpoly_ntt_to_int(logn, tmp6);
		mqpoly_int_to_signed(logn, tmp6);

		/* tmp6  <- z0 + (c*F mod q)/q  (NTT mod q') */
		mq2poly_signed_to_mod(logn, tmp6);
		mq2poly_mulconst(logn, tmp6, MQ2_IQ);
		mq2poly_signed_to_mod(logn, tmp18);
		mq2poly_add(logn, tmp6, tmp18);
		mq2poly_NTT(logn, tmp6);

		/* tmp16 <- z1 - (c*f mod q)/q  (NTT mod q') */
		mq2poly_signed_to_mod(logn, tmp8);
		mq2poly_mulconst(logn, tmp8, MQ2_IQ);
		mq2poly_signed_to_mod(logn, tmp16);
		mq2poly_sub(logn, tmp16, tmp8);
		mq2poly_NTT(logn, tmp16);

		/* tmp0  <- f mod q'  (NTT mod q') */
		mq2poly_small_to_mod(logn, (int8_t *)tmp12, tmp0);
		mq2poly_NTT(logn, tmp0);

		/* tmp10 <- F mod q'  (NTT mod q') */
		mq2poly_small_to_mod(logn, F, tmp10);
		mq2poly_NTT(logn, tmp10);

		/* tmp6  <- s1 = f*(z0 + (c*F mod q)/q)
		               + F*(z1 - (c*f mod q)/q)  (normalized) */
		mq2poly_mul_ntt(logn, tmp6, tmp0);
		mq2poly_mul_ntt(logn, tmp16, tmp10);
		mq2poly_add(logn, tmp6, tmp16);
		mq2poly_iNTT(logn, tmp6);
		mq2poly_mod_to_signed(logn, tmp6);

		/* At this point:
		   tmp2    c mod q  (NTT mod q)
		   tmp4    f mod q  (NTT mod q)
		   tmp6    s1  (normalized) */

		/* tmp0  <- g mod q  (NTT mod q)
		   (g[] into tmp12) */
		KEY_DECODE(logn, sign_key_fgF + flen, (int8_t *)tmp12, nbits);

		mqpoly_small_to_int(logn, (int8_t *)tmp12, tmp0);
		mqpoly_int_to_ntt(logn, tmp0);

		/* tmp0  <- h = g/f mod q  (NTT mod q) */
		mqpoly_div_ntt(logn, tmp0, tmp4, tmp12);

		/* tmp4  <- s1 mod q  (NTT mod q) */
		memcpy(tmp4, tmp6, n * sizeof(uint16_t));
		mqpoly_signed_to_int(logn, tmp4);
		mqpoly_int_to_ntt(logn, tmp4);

		/* tmp2  <- s0 = c - s1*h mod q  (normalized) */
		mqpoly_mul_ntt(logn, tmp4, tmp0);
		mqpoly_sub(logn, tmp2, tmp4);
		mqpoly_ntt_to_int(logn, tmp2);
		mqpoly_int_to_signed(logn, tmp2);

		/* We have the putative signature (s0, s1) in (tmp2, tmp6).
		   This signature is acceptable if the L2 and infinity
		   norms of (s0, s1) are low engouh, and s1 can be encoded
		   in the allocated output size. */
		uint32_t sqn0 = mqpoly_sqnorm_binf_signed(
			logn, (int16_t *)tmp2);
		uint32_t sqn1 = mqpoly_sqnorm_binf_signed(
			logn, (int16_t *)tmp6);
		uint32_t sqn = (sqn0 + sqn1) | ((sqn0 | sqn1) & 0x80000000);
		if (!mqpoly_sqnorm_is_acceptable(logn, sqn)) {
			continue;
		}

#if FNDSA_FALCON_R3
		/* Falcon mode: output the raw s2 polynomial (int16, host order)
		   after the header byte and the nonce. The norm checks above
		   (Round 3 L2 bound, plus the FN-DSA infinity-norm bound, which
		   only makes the output a subset of valid Falcon signatures)
		   already passed. */
		memcpy(sig + 41, tmp6, n * sizeof(int16_t));
		sig[0] = 0x30 + logn;
		ret = 41 + n * sizeof(int16_t);
		break;
#else
		size_t sig_len = FNDSA_SIGNATURE_SIZE(logn);
		if (comp_encode(logn,
			(int16_t *)tmp6, sig + 41, sig_len - 41))
		{
			/* Success! */
			sig[0] = 0x30 + logn;
			ret = sig_len;
			break;
		}
#endif
	}

#if FNDSA_SSE2
	_MM_SET_ROUNDING_MODE(round_mode);
#endif
	return ret;
}
