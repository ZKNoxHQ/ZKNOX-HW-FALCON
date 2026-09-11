/*
 * Gaussian sampling.
 */

#include "fndsa_sign_inner.h"

/* Union type to get easier access to values with SIMD intrinsics. */
typedef union {
	fpr f;
#if FNDSA_NEON
	float64x1_t v;
#endif
#if FNDSA_RV64D
	f64 v;
#endif
} fpr_u;

/* 1/(2*(1.8205^2)) */
#define INV_2SQRSIGMA0   FPR(5435486223186882, -55)

/* For logn = 1 to 10, n = 2^logn:
      q = 12289
      gs_norm = (117/100)*sqrt(q)
      bitsec = max(2, n/4)
      eps = 1/sqrt(bitsec*2^64)
      smoothz2n = sqrt(log(4*n*(1 + 1/eps))/pi)/sqrt(2*pi)
      sigma = smoothz2n*gs_norm
      sigma_min = sigma/gs_norm = smoothz2n
   We store precomputed values for 1/sigma and for sigma_min, indexed
   by logn. */
static const fpr_u INV_SIGMA[] = {
	{ FPR_ZERO },                     /* unused */
	{ FPR(7961475618707097, -60) },   /* 0.0069054793295940881528 */
	{ FPR(7851656902127320, -60) },   /* 0.0068102267767177965681 */
	{ FPR(7746260754658859, -60) },   /* 0.0067188101910722700565 */
	{ FPR(7595833604889141, -60) },   /* 0.0065883354370073655600 */
	{ FPR(7453842886538220, -60) },   /* 0.0064651781207602890978 */
	{ FPR(7319528409832599, -60) },   /* 0.0063486788828078985744 */
	{ FPR(7192222552237877, -60) },   /* 0.0062382586529084365056 */
	{ FPR(7071336252758509, -60) },   /* 0.0061334065020930252290 */
	{ FPR(6956347512113097, -60) },   /* 0.0060336696681577231923 */
	{ FPR(6846791885593314, -60) }    /* 0.0059386453095331150985 */
};
static const fpr_u SIGMA_MIN[] = {
	{ FPR_ZERO },                     /* unused */
	{ FPR(5028307297130123, -52) },   /* 1.1165085072329102589 */
	{ FPR(5098636688852518, -52) },   /* 1.1321247692325272406 */
	{ FPR(5168009084304506, -52) },   /* 1.1475285353733668685 */
	{ FPR(5270355833453349, -52) },   /* 1.1702540788534828940 */
	{ FPR(5370752584786614, -52) },   /* 1.1925466358390344011 */
	{ FPR(5469306724145091, -52) },   /* 1.2144300507766139921 */
	{ FPR(5566116128735780, -52) },   /* 1.2359260567719808790 */
	{ FPR(5661270305715104, -52) },   /* 1.2570545284063214163 */
	{ FPR(5754851361258101, -52) },   /* 1.2778336969128335860 */
	{ FPR(5846934829975396, -52) }    /* 1.2982803343442918540 */
};

/* log(2) */
#define LOG2   FPR(6243314768165359, -53)

/* 1/log(2) */
#define INV_LOG2   FPR(6497320848556798, -52)

/* We access the PRNG through macros so that they can be overridden at
   compile-time by some internal test routine. */
#ifndef prng_init
#define prng_init(pc, seed, seed_len)   do { \
		shake_init(pc, 256); \
		shake_inject(pc, seed, seed_len); \
		shake_flip(pc); \
	} while (0)
#define prng_next_u8    shake_next_u8
#define prng_next_u16   shake_next_u16
#define prng_next_u64   shake_next_u64
#endif

/* fndsa_gaussian0_helper() performs the sampling for the half-Gaussian,
   using (lo >> 1) | (hi << 63) as look-up value (79 bits; low bit of lo
   is ignored). */
#if FNDSA_ASM_CORTEXM4
int32_t fndsa_gaussian0_helper(uint64_t lo, uint32_t hi);
#else
static inline int32_t
fndsa_gaussian0_helper(uint64_t lo, uint32_t hi)
{
	/* Values from Table 5 (Distribution for BaseSampler), split into
	   three chunks of 31, 24 and 24 bits, in high-to-low order,
	   respectively. */
	static const uint32_t GAUSS0[][3] = {
		{ 1375468055,  6936092,  9176346 },
		{  711562636,  1023934, 15582455 },
		{  289335016,  4826132, 14746371 },
		{   90749601, 12313548, 10843417 },
		{   21676598,  5732767,  9419414 },
		{    3908963, 11171514,  6206010 },
		{     529006, 11146683, 11891888 },
		{      53503, 15610582, 11661180 },
		{       4032,  7095613, 11671091 },
		{        225, 16701698,   407118 },
		{          9,  6787688,  1638204 },
		{          0,  4870085,  8687822 },
		{          0,   111406, 13946073 },
		{          0,     1887, 12017202 },
		{          0,       23, 11452285 },
		{          0,        0,  3689579 },
		{          0,        0,    25354 },
		{          0,        0,      129 }
	};

	/* Split the 79-bit value into three words of 24, 24 and 31 bits
	   (in low-to-high order). */
	uint32_t v0 = ((uint32_t)lo >> 1) & 0x00FFFFFF;
	uint32_t v1 = (uint32_t)(lo >> 25) & 0x00FFFFFF;
	uint32_t v2 = (uint32_t)(lo >> 49) | (hi << 15);

	/* Sampled value is z such that v0..v2 is lower than the first
	   z elements of the table. */
	int32_t z = 0;
	for (size_t i = 0; i < (sizeof GAUSS0) / sizeof(GAUSS0[0]); i ++) {
		uint32_t cc;
		cc = (v0 - GAUSS0[i][2]) >> 31;
		cc = (v1 - GAUSS0[i][1] - cc) >> 31;
		cc = (v2 - GAUSS0[i][0] - cc) >> 31;
		z += (int32_t)cc;
	}
	return z;
}
#endif

#define GAUSSIAN(ss, z0, b)   do { \
		uint64_t lo = prng_next_u64(&ss->pc); \
		uint32_t hi = prng_next_u16(&ss->pc); \
		(b) = (uint32_t)lo & 1; \
		(z0) = fndsa_gaussian0_helper(lo, hi); \
	} while (0)

#if FNDSA_SSE2
/* ========================= SSE2 IMPLEMENTATION ========================= */

/* Input: 0 <= x < log(2)
   Output: trunc(x*2^63) */
TARGET_SSE2
static inline int64_t
mtwop63(__m128d x)
{
#if FNDSA_64
	static const union {
		fpr f[2];
		__m128d x;
	} twop63 = { {
		FPR(4503599627370496, 11),
		FPR(4503599627370496, 11),
	} };

	return _mm_cvttsd_si64(_mm_mul_sd(x, twop63.x));
#else
	/* 32-bit x86 does not have an SSE2 opcode to convert floating-point
	   values to 64-bit integers, only 32-bit signed integers. We must
	   do the conversion in three steps with factor 2^21. */
	static const union {
		fpr f[2];
		__m128d x;
	} twop21 = { {
		FPR(4503599627370496, -31),
		FPR(4503599627370496, -31),
	} };
	x = _mm_mul_sd(x, twop21.x);
	int32_t z2 = _mm_cvttsd_si32(x);
	x = _mm_sub_sd(x, _mm_cvtsi32_sd(_mm_setzero_pd(), z2));
	x = _mm_mul_sd(x, twop21.x);
	int32_t z1 = _mm_cvttsd_si32(x);
	x = _mm_sub_sd(x, _mm_cvtsi32_sd(_mm_setzero_pd(), z1));
	x = _mm_mul_sd(x, twop21.x);
	int32_t z0 = _mm_cvttsd_si32(x);
	return ((int64_t)z2 << 42) + ((int64_t)z1 << 21) + (int64_t)z0;
#endif
}

/* Compute ccs*exp(-x)*2^63, rounded to an integer. This function assumes
   that 0 <= x < log(2), and 0 <= ccs <= 1. It returns a value in [0,2^63]. */
TARGET_SSE2
static inline uint64_t
expm_p63(__m128d x, __m128d ccs)
{
	/* The polynomial approximation of exp(-x) is from FACCT:
	      https://eprint.iacr.org/2018/1234
	   Specifically, the values are extracted from the implementation
	   referenced by the FACCT paper, available at:
	      https://github.com/raykzhao/gaussian  */
	static const uint64_t EXPM_COEFFS[] = {
		0x00000004741183A3,
		0x00000036548CFC06,
		0x0000024FDCBF140A,
		0x0000171D939DE045,
		0x0000D00CF58F6F84,
		0x000680681CF796E3,
		0x002D82D8305B0FEA,
		0x011111110E066FD0,
		0x0555555555070F00,
		0x155555555581FF00,
		0x400000000002B400,
		0x7FFFFFFFFFFF4800,
		0x8000000000000000
	};

	uint64_t y = EXPM_COEFFS[0];
	uint64_t z = (uint64_t)mtwop63(x) << 1;
	uint64_t w = (uint64_t)mtwop63(ccs) << 1;
	/* sigma_min is not tight, so ccs < 1 and w is not truncated to 0 */
#if FNDSA_64
	/* On 64-bit x86, we have 64x64->128 multiplication, then we can use
	   it, it's normally constant-time.
	   MSVC uses a different syntax for this operation. */
	for (size_t i = 1; i < (sizeof EXPM_COEFFS) / sizeof(uint64_t); i ++) {
#if defined _MSC_VER
		y = EXPM_COEFFS[i] - __umulh(z, y);
#else
		unsigned __int128 c =
			(unsigned __int128)z * (unsigned __int128)y;
		y = EXPM_COEFFS[i] - (uint64_t)(c >> 64);
#endif
	}
#if defined _MSC_VER
	y = __umulh(w, y);
#else
	y = (uint64_t)(((unsigned __int128)w * (unsigned __int128)y) >> 64);
#endif
#else
	/* On 32-bit x86, no 64x64->128 multiplication, we must use
	   four 32x32->64 multiplications. */
	uint32_t z0 = (uint32_t)z, z1 = (uint32_t)(z >> 32);
	uint32_t w0 = (uint32_t)w, w1 = (uint32_t)(w >> 32);

	for (size_t i = 1; i < (sizeof EXPM_COEFFS) / sizeof(uint64_t); i ++) {
		uint32_t y0 = (uint32_t)y, y1 = (uint32_t)(y >> 32);
		uint64_t f = (uint64_t)z0 * (uint64_t)y0;
		uint64_t a = (uint64_t)z0 * (uint64_t)y1 + (f >> 32);
		uint64_t b = (uint64_t)z1 * (uint64_t)y0;
		uint64_t c = (a >> 32) + (b >> 32)
			+ (((uint64_t)(uint32_t)a
			  + (uint64_t)(uint32_t)b) >> 32)
			+ (uint64_t)z1 * (uint64_t)y1;
		y = EXPM_COEFFS[i] - c;
	}
	uint32_t y0 = (uint32_t)y, y1 = (uint32_t)(y >> 32);
	uint64_t f = (uint64_t)w0 * (uint64_t)y0;
	uint64_t a = (uint64_t)w0 * (uint64_t)y1 + (f >> 32);
	uint64_t b = (uint64_t)w1 * (uint64_t)y0;
	y = (a >> 32) + (b >> 32)
		+ (((uint64_t)(uint32_t)a + (uint64_t)(uint32_t)b) >> 32)
		+ (uint64_t)w1 * (uint64_t)y1;
#endif
	return y;
}

/* Sample a bit with probability ccs*exp(-x) (for x >= 0). */
TARGET_SSE2
static inline int
ber_exp(sampler_state *ss, __m128d x, __m128d ccs)
{
	static union { fpr f[2]; __m128d x; }
		LOG2_u = { { LOG2, LOG2 } },
		INV_LOG2_u = { { INV_LOG2, INV_LOG2 } };

	/* Reduce x modulo log(2): x = s*log(2) + r, with s an integer,
	   and 0 <= r < log(2). We can use a truncating conversion because
	   x >= 0. Moreover, x is small, so we can stick to 32-bit values. */
	int32_t si = _mm_cvttsd_si32(_mm_mul_sd(x, INV_LOG2_u.x));
	__m128d r = _mm_sub_sd(x,
		_mm_mul_sd(_mm_cvtsi32_sd(_mm_setzero_pd(), si), LOG2_u.x));

	/* If s >= 64, sigma = 1.2, r = 0 and b = 1, then we get s >= 64
	   if the half-Gaussian produced z >= 13, which happens with
	   probability about 2^(-32). When s >= 64, ber_exp() will return
	   true with probability less than 2^(-64), so we can simply
	   saturate s at 63 (the bias introduced here is lower than 2^(-96),
	   and would require about 2^192 samplings to be detectable, which
	   is way beyond the formal bound of 2^64 signatures with the
	   same key. */
	uint32_t s = (uint32_t)si;
	s |= (uint32_t)(63 - s) >> 26;
	s &= 63;

	/* Compute ccs*exp(-x). Since x = s*log(2) + r, we compute
	   ccs*exp(-r)/2^s. We know that 0 <= r < log(2), so we can
	   use expm_p63(), which yields a result scaled by 63 bits. We
	   scale it up 1 bit further, then right-shift by s bits.

	   We subtract 1 to make sure that the value fits on 64 bits
	   (i.e. if r = 0 then we may get 2^64 and we prefer 2^64-1
	   in that case, to avoid the overflow). The bias is negligible
	   since expm_p63() has precision only 51 bits or so. */
	uint64_t z = fpr_ursh((expm_p63(r, ccs) << 1) - 1, s);

	/* Sample a bit. We lazily compare the value z with a uniform 64-bit
	   integer, consuming only as many bytes as necessary. Since the PRNG
	   is cryptographically strong, we leak no information from the
	   conditional jumps below. */
	for (int i = 56; i >= 0; i -= 8) {
		unsigned w = prng_next_u8(&ss->pc);
		unsigned bz = (unsigned)(z >> i) & 0xFF;
		if (w != bz) {
			return w < bz;
		}
	}
	return 0;
}

#if 0
/* disabled code for one-time gathering of test vectors */
fpr KAT_SAMPLER_mu[1024];
fpr KAT_SAMPLER_isigma[1024];
int16_t KAT_SAMPLER_out[1024];
size_t KAT_SAMPLER_ptr = 0;
#endif

TARGET_SSE2
static int32_t
sampler_next_sse2(sampler_state *ss, __m128d mu, __m128d isigma)
{
#if 0
/* disabled code for one-time gathering of test vectors */
	if (KAT_SAMPLER_ptr >= 1024) {
		extern void exid(int);
		exit(43);
	}
	union {
		double d;
		fpr f;
	} KAT_SAMPLER_t;
	_mm_store_sd(&KAT_SAMPLER_t.d, mu);
	KAT_SAMPLER_mu[KAT_SAMPLER_ptr] = KAT_SAMPLER_t.f;
	_mm_store_sd(&KAT_SAMPLER_t.d, isigma);
	KAT_SAMPLER_isigma[KAT_SAMPLER_ptr] = KAT_SAMPLER_t.f;
#endif

	static union { fpr f[2]; __m128d x; }
		HALF_u = { {
			FPR(4503599627370496, -53),
			FPR(4503599627370496, -53)
		} },
		INV_2SQRSIGMA0_u = { {
			INV_2SQRSIGMA0, INV_2SQRSIGMA0
		} };

	/* Split center mu into s + r, for an integer s, and 0 <= r < 1. */
	int32_t s = _mm_cvttsd_si32(mu);
	s -= _mm_comilt_sd(mu, _mm_cvtsi32_sd(_mm_setzero_pd(), s));
	__m128d r = _mm_sub_sd(mu, _mm_cvtsi32_sd(_mm_setzero_pd(), s));

	/* dss = 1/(2*sigma^2) = 0.5*(isigma^2)  */
	__m128d dss = _mm_mul_sd(_mm_mul_sd(isigma, isigma), HALF_u.x);

	/* ccs = sigma_min / sigma = sigma_min * isigma  */
	__m128d ccs = _mm_mul_sd(isigma,
		_mm_load_sd((const double *)SIGMA_MIN + ss->logn));

	/* We sample on centre r. */
	for (;;) {
		/* Sample z for a Gaussian distribution (non-negative only),
		   then get a random bit b to turn the sampling into a
		   bimodal distribution (we use z+1 if b = 1, or -z
		   otherwise). */
		int32_t z0, b;
		GAUSSIAN(ss, z0, b);
		int32_t z = b + ((b << 1) - 1) * z0;

		/* Rejection sampling. We want a Gaussian centred on r,
		   but we sampled against a bimodal distribution (with
		   "centres" at 0 and 1). However, we know that z is
		   always in the range where our sampling distribution is
		   greater than the Gaussian distribution, so rejection works.

		   We got z from distribution:
		      G(z) = exp(-((z-b)^2)/(2*sigma0^2))
		   We target distribution:
		      S(z) = exp(-((z-r)^2)/(2*signa^2))
		   Rejection sampling works by keeping the value z with
		   probability S(z)/G(z), and starting again otherwise.
		   This requires S(z) <= G(z), which is the case here.
		   Thus, we simply need to keep our z with probability:
		      P = exp(-x)
		   where:
		      x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
		   Here, we scale up the Bernouilli distribution, which
		   makes rejection more probable, but also makes the
		   rejection rate sufficiently decorrelated from the Gaussian
		   centre and standard deviation, so that measurement of the
		   rejection rate does not leak enough usable information
		   to attackers (which is how the implementation can claim
		   to be "constant-time").  */
		__m128d x = _mm_sub_sd(_mm_cvtsi32_sd(_mm_setzero_pd(), z), r);
		x = _mm_mul_sd(_mm_mul_sd(x, x), dss);
		x = _mm_sub_sd(x, _mm_mul_sd(
			_mm_cvtsi32_sd(_mm_setzero_pd(), z0 * z0),
			INV_2SQRSIGMA0_u.x));
		if (ber_exp(ss, x, ccs)) {
			/* disabled one-time test vector gathering code
			KAT_SAMPLER_out[KAT_SAMPLER_ptr ++] = s + z;
			*/
			return s + z;
		}
	}
}

/* see sign_inner.h */
TARGET_SSE2
int32_t
sampler_next(sampler_state *ss, fpr mu, fpr isigma)
{
	return sampler_next_sse2(ss,
		_mm_load_sd((double *)&mu),
		_mm_load_sd((double *)&isigma));
}

#elif FNDSA_NEON
/* ========================= NEON IMPLEMENTATION ========================= */

/* Input: 0 <= x < log(2)
   Output: trunc(x*2^63) */
TARGET_NEON
static inline int64_t
mtwop63(float64x1_t x)
{
	static const fpr_u twop63 = { FPR(4503599627370496, 11) };
	return vget_lane_s64(vcvt_s64_f64(vmul_f64(x, twop63.v)), 0);
}

/* Compute ccs*exp(-x)*2^63, rounded to an integer. This function assumes
   that 0 <= x < log(2), and 0 <= ccs <= 1. It returns a value in [0,2^63]. */
TARGET_NEON
static inline uint64_t
expm_p63(float64x1_t x, float64x1_t ccs)
{
	/* The polynomial approximation of exp(-x) is from FACCT:
	      https://eprint.iacr.org/2018/1234
	   Specifically, the values are extracted from the implementation
	   referenced by the FACCT paper, available at:
	      https://github.com/raykzhao/gaussian  */
	static const uint64_t EXPM_COEFFS[] = {
		0x00000004741183A3,
		0x00000036548CFC06,
		0x0000024FDCBF140A,
		0x0000171D939DE045,
		0x0000D00CF58F6F84,
		0x000680681CF796E3,
		0x002D82D8305B0FEA,
		0x011111110E066FD0,
		0x0555555555070F00,
		0x155555555581FF00,
		0x400000000002B400,
		0x7FFFFFFFFFFF4800,
		0x8000000000000000
	};

	uint64_t y = EXPM_COEFFS[0];
	uint64_t z = (uint64_t)mtwop63(x) << 1;
	uint64_t w = (uint64_t)mtwop63(ccs) << 1;
	/* sigma_min is not tight, so ccs < 1 and w is not truncated to 0 */

	/* We assume here that 64x64->128 multiplications are constant-time,
	   which is not exactly true on some aarch64 systems (e.g. ARM
	   Cortex A53 and A55 return the result one cycle earlier when
	   the operands fit on 32 bits).
	   ARM compiler calls the 128-bit type '__uint128_t' while GCC
	   and Clang use 'unsigned __int128'. */
	for (size_t i = 1; i < (sizeof EXPM_COEFFS) / sizeof(uint64_t); i ++) {
#if defined __GNUC__ || defined __clang__
		unsigned __int128 c =
			(unsigned __int128)z * (unsigned __int128)y;
		y = EXPM_COEFFS[i] - (uint64_t)(c >> 64);
#else
		__uint128_t c = (__uint128_t)z * (__uint128_t)y;
		y = EXPM_COEFFS[i] - (uint64_t)(c >> 64);
#endif
	}
#if defined __GNUC__ || defined __clang__
	y = (uint64_t)(((unsigned __int128)w * (unsigned __int128)y) >> 64);
#else
	y = (uint64_t)(((__uint128_t)w * (__uint128_t)y) >> 64);
#endif
	return y;
}

/* Sample a bit with probability ccs*exp(-x) (for x >= 0). */
TARGET_NEON
static inline int
ber_exp(sampler_state *ss, float64x1_t x, float64x1_t ccs)
{
	static const fpr_u LOG2_u = { LOG2 };
	static const fpr_u INV_LOG2_u = { INV_LOG2 };

	/* Reduce x modulo log(2): x = s*log(2) + r, with s an integer,
	   and 0 <= r < log(2). We can use a truncating conversion because
	   x >= 0. Moreover, x is small, so we can stick to 32-bit values. */
	int32_t si = (int32_t)vget_lane_s64(
		vcvt_s64_f64(vmul_f64(x, INV_LOG2_u.v)), 0);
	float64x1_t r = vsub_f64(x,
		vmul_f64(vcvt_f64_s64(vcreate_s64(si)), LOG2_u.v));

	/* If s >= 64, sigma = 1.2, r = 0 and b = 1, then we get s >= 64
	   if the half-Gaussian produced z >= 13, which happens with
	   probability about 2^(-32). When s >= 64, ber_exp() will return
	   true with probability less than 2^(-64), so we can simply
	   saturate s at 63 (the bias introduced here is lower than 2^(-96),
	   and would require about 2^192 samplings to be detectable, which
	   is way beyond the formal bound of 2^64 signatures with the
	   same key. */
	uint32_t s = (uint32_t)si;
	s |= (uint32_t)(63 - s) >> 26;
	s &= 63;

	/* Compute ccs*exp(-x). Since x = s*log(2) + r, we compute
	   ccs*exp(-r)/2^s. We know that 0 <= r < log(2), so we can
	   use expm_p63(), which yields a result scaled by 63 bits. We
	   scale it up 1 bit further, then right-shift by s bits.

	   We subtract 1 to make sure that the value fits on 64 bits
	   (i.e. if r = 0 then we may get 2^64 and we prefer 2^64-1
	   in that case, to avoid the overflow). The bias is negligible
	   since expm_p63() has precision only 51 bits or so. */
	uint64_t z = fpr_ursh((expm_p63(r, ccs) << 1) - 1, s);

	/* Sample a bit. We lazily compare the value z with a uniform 64-bit
	   integer, consuming only as many bytes as necessary. Since the PRNG
	   is cryptographically strong, we leak no information from the
	   conditional jumps below. */
	for (int i = 56; i >= 0; i -= 8) {
		unsigned w = prng_next_u8(&ss->pc);
		unsigned bz = (unsigned)(z >> i) & 0xFF;
		if (w != bz) {
			return w < bz;
		}
	}
	return 0;
}

TARGET_NEON
static int32_t
sampler_next_neon(sampler_state *ss, float64x1_t mu, float64x1_t isigma)
{
	static const fpr_u HALF_u = { FPR(4503599627370496, -53) };
	static const fpr_u INV_2SQRSIGMA0_u = { INV_2SQRSIGMA0 };

	/* Split center mu into s + r, for an integer s, and 0 <= r < 1. */
	int32_t s = (int32_t)vcvtmd_s64_f64(mu);
	float64x1_t r = vsub_f64(mu, vcvt_f64_s64(vcreate_s64(s)));

	/* dss = 1/(2*sigma^2) = 0.5*(isigma^2)  */
	float64x1_t dss = vmul_f64(vmul_f64(isigma, isigma), HALF_u.v);

	/* ccs = sigma_min / sigma = sigma_min * isigma  */
	float64x1_t ccs = vmul_f64(isigma, SIGMA_MIN[ss->logn].v);

	/* We sample on centre r. */
	for (;;) {
		/* Sample z for a Gaussian distribution (non-negative only),
		   then get a random bit b to turn the sampling into a
		   bimodal distribution (we use z+1 if b = 1, or -z
		   otherwise). */
		int32_t z0, b;
		GAUSSIAN(ss, z0, b);
		int32_t z = b + ((b << 1) - 1) * z0;

		/* Rejection sampling. We want a Gaussian centred on r,
		   but we sampled against a bimodal distribution (with
		   "centres" at 0 and 1). However, we know that z is
		   always in the range where our sampling distribution is
		   greater than the Gaussian distribution, so rejection works.

		   We got z from distribution:
		      G(z) = exp(-((z-b)^2)/(2*sigma0^2))
		   We target distribution:
		      S(z) = exp(-((z-r)^2)/(2*signa^2))
		   Rejection sampling works by keeping the value z with
		   probability S(z)/G(z), and starting again otherwise.
		   This requires S(z) <= G(z), which is the case here.
		   Thus, we simply need to keep our z with probability:
		      P = exp(-x)
		   where:
		      x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
		   Here, we scale up the Bernouilli distribution, which
		   makes rejection more probable, but also makes the
		   rejection rate sufficiently decorrelated from the Gaussian
		   centre and standard deviation, so that measurement of the
		   rejection rate does not leak enough usable information
		   to attackers (which is how the implementation can claim
		   to be "constant-time").  */
		float64x1_t x = vsub_f64(vcvt_f64_s64(vcreate_s64(z)), r);
		x = vmul_f64(vmul_f64(x, x), dss);
		x = vsub_f64(x, vmul_f64(
			vcvt_f64_s64(vcreate_s64(z0 * z0)),
			INV_2SQRSIGMA0_u.v));
		if (ber_exp(ss, x, ccs)) {
			return s + z;
		}
	}
}

/* see sign_inner.h */
TARGET_NEON
int32_t
sampler_next(sampler_state *ss, fpr mu, fpr isigma)
{
	return sampler_next_neon(ss,
		vld1_f64((const float64_t *)&mu),
		vld1_f64((const float64_t *)&isigma));
}

#elif FNDSA_RV64D
/* ========================= RISC-V IMPLEMENTATION ======================= */

/* Input: 0 <= x < log(2)
   Output: trunc(x*2^63) */
static inline int64_t
mtwop63(f64 x)
{
	static const fpr_u twop63 = { FPR(4503599627370496, 11) };
	return f64_trunc(f64_mul(x, twop63.v));
}

static inline uint64_t
expm_p63(f64 x, f64 ccs)
{
	/* The polynomial approximation of exp(-x) is from FACCT:
	      https://eprint.iacr.org/2018/1234
	   Specifically, the values are extracted from the implementation
	   referenced by the FACCT paper, available at:
	      https://github.com/raykzhao/gaussian  */
	static const uint64_t EXPM_COEFFS[] = {
		0x00000004741183A3,
		0x00000036548CFC06,
		0x0000024FDCBF140A,
		0x0000171D939DE045,
		0x0000D00CF58F6F84,
		0x000680681CF796E3,
		0x002D82D8305B0FEA,
		0x011111110E066FD0,
		0x0555555555070F00,
		0x155555555581FF00,
		0x400000000002B400,
		0x7FFFFFFFFFFF4800,
		0x8000000000000000
	};

	uint64_t y = EXPM_COEFFS[0];
	uint64_t z = (uint64_t)mtwop63(x) << 1;
	uint64_t w = (uint64_t)mtwop63(ccs) << 1;
	/* sigma_min is not tight, so ccs < 1 and w is not truncated to 0 */

	/* We assume here that 64x64->128 multiplications are constant-time
	   and that the compiler is GCC/Clang compatible (i.e. supports
	   the 'unsigned __int128' type). */
	for (size_t i = 1; i < (sizeof EXPM_COEFFS) / sizeof(uint64_t); i ++) {
		unsigned __int128 c =
			(unsigned __int128)z * (unsigned __int128)y;
		y = EXPM_COEFFS[i] - (uint64_t)(c >> 64);
	}
	y = (uint64_t)(((unsigned __int128)w * (unsigned __int128)y) >> 64);
	return y;
}

/* Sample a bit with probability ccs*exp(-x) (for x >= 0). */
static inline int
ber_exp(sampler_state *ss, f64 x, f64 ccs)
{
	static const fpr_u LOG2_u = { LOG2 };
	static const fpr_u INV_LOG2_u = { INV_LOG2 };

	/* Reduce x modulo log(2): x = s*log(2) + r, with s an integer,
	   and 0 <= r < log(2). We can use f64_trunc() because x >= 0. */
	int32_t si = (int32_t)f64_trunc(f64_mul(x, INV_LOG2_u.v));
	f64 r = f64_sub(x, f64_mul(f64_of(si), LOG2_u.v));

	/* If s >= 64, sigma = 1.2, r = 0 and b = 1, then we get s >= 64
	   if the half-Gaussian produced z >= 13, which happens with
	   probability about 2^(-32). When s >= 64, ber_exp() will return
	   true with probability less than 2^(-64), so we can simply
	   saturate s at 63 (the bias introduced here is lower than 2^(-96),
	   and would require about 2^192 samplings to be detectable, which
	   is way beyond the formal bound of 2^64 signatures with the
	   same key. */
	uint32_t s = (uint32_t)si;
	s |= (uint32_t)(63 - s) >> 26;
	s &= 63;

	/* Compute ccs*exp(-x). Since x = s*log(2) + r, we compute
	   ccs*exp(-r)/2^s. We know that 0 <= r < log(2), so we can
	   use expm_p63(), which yields a result scaled by 63 bits. We
	   scale it up 1 bit further, then right-shift by s bits.

	   We subtract 1 to make sure that the value fits on 64 bits
	   (i.e. if r = 0 then we may get 2^64 and we prefer 2^64-1
	   in that case, to avoid the overflow). The bias is negligible
	   since expm_p63() has precision only 51 bits or so. */
	uint64_t z = fpr_ursh((expm_p63(r, ccs) << 1) - 1, s);

	/* Sample a bit. We lazily compare the value z with a uniform 64-bit
	   integer, consuming only as many bytes as necessary. Since the PRNG
	   is cryptographically strong, we leak no information from the
	   conditional jumps below. */
	for (int i = 56; i >= 0; i -= 8) {
		unsigned w = prng_next_u8(&ss->pc);
		unsigned bz = (unsigned)(z >> i) & 0xFF;
		if (w != bz) {
			return w < bz;
		}
	}
	return 0;
}

static int32_t
sampler_next_rv64d(sampler_state *ss, f64 mu, f64 isigma)
{
	static const fpr_u INV_2SQRSIGMA0_u = { INV_2SQRSIGMA0 };

	/* Split center mu into s + r, for an integer s, and 0 <= r < 1. */
	int64_t s = f64_floor(mu);
	f64 r = f64_sub(mu, f64_of(s));

	/* dss = 1/(2*sigma^2) = 0.5*(isigma^2)  */
	f64 dss = f64_half(f64_sqr(isigma));

	/* ccs = sigma_min / sigma = sigma_min * isigma  */
	f64 ccs = f64_mul(isigma, SIGMA_MIN[ss->logn].v);

	/* We sample on centre r. */
	for (;;) {
		/* Sample z for a Gaussian distribution (non-negative only),
		   then get a random bit b to turn the sampling into a
		   bimodal distribution (we use z+1 if b = 1, or -z
		   otherwise). */
		int32_t z0, b;
		GAUSSIAN(ss, z0, b);
		int32_t z = b + ((b << 1) - 1) * z0;

		/* Rejection sampling. We want a Gaussian centred on r,
		   but we sampled against a bimodal distribution (with
		   "centres" at 0 and 1). However, we know that z is
		   always in the range where our sampling distribution is
		   greater than the Gaussian distribution, so rejection works.

		   We got z from distribution:
		      G(z) = exp(-((z-b)^2)/(2*sigma0^2))
		   We target distribution:
		      S(z) = exp(-((z-r)^2)/(2*signa^2))
		   Rejection sampling works by keeping the value z with
		   probability S(z)/G(z), and starting again otherwise.
		   This requires S(z) <= G(z), which is the case here.
		   Thus, we simply need to keep our z with probability:
		      P = exp(-x)
		   where:
		      x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
		   Here, we scale up the Bernouilli distribution, which
		   makes rejection more probable, but also makes the
		   rejection rate sufficiently decorrelated from the Gaussian
		   centre and standard deviation, so that measurement of the
		   rejection rate does not leak enough usable information
		   to attackers (which is how the implementation can claim
		   to be "constant-time").  */
		f64 x = f64_mul(f64_sqr(f64_sub(f64_of(z), r)), dss);
		x = f64_sub(x, f64_mul(f64_of(z0 * z0), INV_2SQRSIGMA0_u.v));
		if (ber_exp(ss, x, ccs)) {
			return (int32_t)s + z;
		}
	}
}

/* see sign_inner.h */
int32_t
sampler_next(sampler_state *ss, fpr mu, fpr isigma)
{
	return sampler_next_rv64d(ss, f64_from_raw(mu), f64_from_raw(isigma));
}

#else
/* ========================= PLAIN IMPLEMENTATION ======================== */

static inline uint64_t
expm_p63(fpr x, fpr ccs)
{
	/* The polynomial approximation of exp(-x) is from FACCT:
	      https://eprint.iacr.org/2018/1234
	   Specifically, the values are extracted from the implementation
	   referenced by the FACCT paper, available at:
	      https://github.com/raykzhao/gaussian  */
	static const uint64_t EXPM_COEFFS[] = {
		0x00000004741183A3,
		0x00000036548CFC06,
		0x0000024FDCBF140A,
		0x0000171D939DE045,
		0x0000D00CF58F6F84,
		0x000680681CF796E3,
		0x002D82D8305B0FEA,
		0x011111110E066FD0,
		0x0555555555070F00,
		0x155555555581FF00,
		0x400000000002B400,
		0x7FFFFFFFFFFF4800,
		0x8000000000000000
	};

	/* TODO: maybe use 64x64->128 multiplications if available? It
	   is a bit tricky to decide, because the plain code is used for
	   unknown architectures, and we do not know if the larger
	   multiplication is constant-time (it often happens that it
	   is not). */

	uint64_t y = EXPM_COEFFS[0];
	uint64_t z = (uint64_t)fpr_trunc(fpr_mul2e(x, 63)) << 1;
	uint32_t z0 = (uint32_t)z, z1 = (uint32_t)(z >> 32);
#if FNDSA_ASM_CORTEXM4
#pragma GCC unroll 12
#endif
	for (size_t i = 1; i < (sizeof EXPM_COEFFS) / sizeof(uint64_t); i ++) {
		uint32_t y0 = (uint32_t)y, y1 = (uint32_t)(y >> 32);
#if FNDSA_ASM_CORTEXM4
		uint32_t tt, r0, r1;
		__asm__(
			"umull	%0, %2, %3, %5\n\t"
			"umull	%0, %1, %3, %6\n\t"
			"umaal	%2, %0, %4, %5\n\t"
			"umaal	%0, %1, %4, %6\n\t"
			: "=&r" (r0), "=&r" (r1), "=&r" (tt)
			: "r" (y0), "r" (y1), "r" (z0), "r" (z1));
		y = EXPM_COEFFS[i] - ((uint64_t)r0 | ((uint64_t)r1 << 32));
#else
		uint64_t f = (uint64_t)z0 * (uint64_t)y0;
		uint64_t a = (uint64_t)z0 * (uint64_t)y1 + (f >> 32);
		uint64_t b = (uint64_t)z1 * (uint64_t)y0;
		uint64_t c = (a >> 32) + (b >> 32)
			+ (((uint64_t)(uint32_t)a
			  + (uint64_t)(uint32_t)b) >> 32)
			+ (uint64_t)z1 * (uint64_t)y1;
		y = EXPM_COEFFS[i] - c;
#endif
	}

	/* The scaling factor must be applied at the end. Since y is now
	   in fixed-point notation, we have to convert the factor to the
	   same format, and we do an extra integer multiplication. */
	/* sigma_min is not tight, so ccs < 1 and w is not truncated to 0 */
	uint64_t w = (uint64_t)fpr_trunc(fpr_mul2e(ccs, 63)) << 1;
	uint32_t w0 = (uint32_t)w, w1 = (uint32_t)(w >> 32);
	uint32_t y0 = (uint32_t)y, y1 = (uint32_t)(y >> 32);
#if FNDSA_ASM_CORTEXM4
	uint32_t tt, r0, r1;
	__asm__(
		"umull	%0, %2, %3, %5\n\t"
		"umull	%0, %1, %3, %6\n\t"
		"umaal	%2, %0, %4, %5\n\t"
		"umaal	%0, %1, %4, %6\n\t"
		: "=&r" (r0), "=&r" (r1), "=&r" (tt)
		: "r" (y0), "r" (y1), "r" (w0), "r" (w1));
	y = (uint64_t)r0 | ((uint64_t)r1 << 32);
#else
	uint64_t f = (uint64_t)w0 * (uint64_t)y0;
	uint64_t a = (uint64_t)w0 * (uint64_t)y1 + (f >> 32);
	uint64_t b = (uint64_t)w1 * (uint64_t)y0;
	y = (a >> 32) + (b >> 32)
		+ (((uint64_t)(uint32_t)a + (uint64_t)(uint32_t)b) >> 32)
		+ (uint64_t)w1 * (uint64_t)y1;
#endif
	return y;
}

/* Sample a bit with probability ccs*exp(-x) (for x >= 0). */
static inline int
ber_exp(sampler_state *ss, fpr x, fpr ccs)
{
	/* Reduce x modulo log(2): x = s*log(2) + r, with s an integer,
	   and 0 <= r < log(2). We can use fpr_trunc() because x >= 0
	   (fpr_trunc() is presumably a bit faster than fpr_floor()). */
	int32_t si = (int32_t)fpr_trunc(fpr_mul(x, INV_LOG2));
	fpr r = fpr_sub(x, fpr_mul(fpr_of32(si), LOG2));

	/* If s >= 64, sigma = 1.2, r = 0 and b = 1, then we get s >= 64
	   if the half-Gaussian produced z >= 13, which happens with
	   probability about 2^(-32). When s >= 64, ber_exp() will return
	   true with probability less than 2^(-64), so we can simply
	   saturate s at 63 (the bias introduced here is lower than 2^(-96),
	   and would require about 2^192 samplings to be detectable, which
	   is way beyond the formal bound of 2^64 signatures with the
	   same key. */
	uint32_t s = (uint32_t)si;
	s |= (uint32_t)(63 - s) >> 26;
	s &= 63;

	/* Compute ccs*exp(-x). Since x = s*log(2) + r, we compute
	   ccs*exp(-r)/2^s. We know that 0 <= r < log(2), so we can
	   use expm_p63(), which yields a result scaled by 63 bits. We
	   scale it up 1 bit further, then right-shift by s bits.

	   We subtract 1 to make sure that the value fits on 64 bits
	   (i.e. if r = 0 then we may get 2^64 and we prefer 2^64-1
	   in that case, to avoid the overflow). The bias is negligible
	   since expm_p63() has precision only 51 bits or so. */
	uint64_t z = fpr_ursh((expm_p63(r, ccs) << 1) - 1, s);

	/* Sample a bit. We lazily compare the value z with a uniform 64-bit
	   integer, consuming only as many bytes as necessary. Since the PRNG
	   is cryptographically strong, we leak no information from the
	   conditional jumps below. */
	for (int i = 56; i >= 0; i -= 8) {
		unsigned w = prng_next_u8(&ss->pc);
		unsigned bz = (unsigned)(z >> i) & 0xFF;
		if (w != bz) {
			return w < bz;
		}
	}
	return 0;
}

/* see sign_inner.h */
#if FNDSA_SAMPLER_PROTECT
/* With the SCA-protected sampler enabled, the plain SamplerZ stays
   available (test/diff tooling) under another name. */
int32_t sampler_next_plain(sampler_state *ss, fpr mu, fpr isigma);
int32_t
sampler_next_plain(sampler_state *ss, fpr mu, fpr isigma)
#else
int32_t
sampler_next(sampler_state *ss, fpr mu, fpr isigma)
#endif
{
	/* Split center mu into s + r, for an integer s, and 0 <= r < 1. */
	int64_t s = fpr_floor(mu);
	fpr r = fpr_sub(mu, fpr_of32((int32_t)s));

	/* dss = 1/(2*sigma^2) = 0.5*(isigma^2)  */
	fpr dss = fpr_half(fpr_sqr(isigma));

	/* ccs = sigma_min / sigma = sigma_min * isigma  */
	fpr ccs = fpr_mul(isigma, SIGMA_MIN[ss->logn].f);

	/* We sample on centre r. */
	for (;;) {
		/* Sample z for a Gaussian distribution (non-negative only),
		   then get a random bit b to turn the sampling into a
		   bimodal distribution (we use z+1 if b = 1, or -z
		   otherwise). */
		int32_t z0, b;
		GAUSSIAN(ss, z0, b);
		int32_t z = b + ((b << 1) - 1) * z0;

		/* Rejection sampling. We want a Gaussian centred on r,
		   but we sampled against a bimodal distribution (with
		   "centres" at 0 and 1). However, we know that z is
		   always in the range where our sampling distribution is
		   greater than the Gaussian distribution, so rejection works.

		   We got z from distribution:
		      G(z) = exp(-((z-b)^2)/(2*sigma0^2))
		   We target distribution:
		      S(z) = exp(-((z-r)^2)/(2*signa^2))
		   Rejection sampling works by keeping the value z with
		   probability S(z)/G(z), and starting again otherwise.
		   This requires S(z) <= G(z), which is the case here.
		   Thus, we simply need to keep our z with probability:
		      P = exp(-x)
		   where:
		      x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
		   Here, we scale up the Bernouilli distribution, which
		   makes rejection more probable, but also makes the
		   rejection rate sufficiently decorrelated from the Gaussian
		   centre and standard deviation, so that measurement of the
		   rejection rate does not leak enough usable information
		   to attackers (which is how the implementation can claim
		   to be "constant-time").  */
		fpr x = fpr_mul(fpr_sqr(fpr_sub(fpr_of32(z), r)), dss);
		x = fpr_sub(x, fpr_mul(fpr_of32(z0 * z0), INV_2SQRSIGMA0));
		if (ber_exp(ss, x, ccs)) {
			return (int32_t)s + z;
		}
	}
}
#endif

/* On Arm Cortex M4, this function must be callable externally so that it
   can be invoked by the assembly implementation of ffsamp_fft_inner(). */
#if FNDSA_ASM_CORTEXM4
#define ffsamp_fft_deepest   fndsa_ffsamp_fft_deepest
NOINLINE void
#else
NOINLINE TARGET_SSE2 TARGET_NEON static void
#endif
ffsamp_fft_deepest(sampler_state *ss, unsigned flags, fpr *tmp)
{
#if FNDSA_SSE2
	/* n = 2
	   t = t0 + t1*X; FFT is t0(i) = t0 + t1*i (already split).
	   a = a0  (since a is self-adjoint)  */
	__m128d a0 = _mm_load_sd((double *)tmp + 2);
	__m128d leaf = _mm_mul_sd(_mm_sqrt_sd(_mm_setzero_pd(), a0),
		_mm_load_sd((const double *)INV_SIGMA + ss->logn));

	/* Elements of dz[] are explored by pairs; base offset
	   is the bit-reversal of a decrementing counter. */
	unsigned j = -- ss->off;
	j = ((j & 0x1C0) >> 6) | (j & 0x038) | ((j & 0x007) << 6);
	j = ((j & 0x124) >> 2) | (j & 0x092) | ((j & 0x049) << 2);
	j >>= (10 - ss->logn);
	unsigned j2 = j + (1u << (ss->logn - 1));

	static const union {
		fpr f[2];
		__m128d x;
	} iq = { { FPR_IQ, FPR_IQ } };

	__m128d t0 = _mm_mul_sd(
		_mm_cvtsi32_sd(_mm_setzero_pd(), ss->dz[j]), iq.x);
	if (!(flags & FLAG_INIT0)) {
		t0 = _mm_add_sd(t0, _mm_load_sd((double *)tmp));
	}
	int32_t z0 = sampler_next_sse2(ss, t0, leaf);
	ss->dz[j] = (int16_t)z0;
	if (!(flags & FLAG_NOOUT)) {
		_mm_store_sd((double *)tmp, _mm_sub_sd(t0,
			_mm_cvtsi32_sd(_mm_setzero_pd(), z0)));
	}

	__m128d t1 = _mm_mul_sd(
		_mm_cvtsi32_sd(_mm_setzero_pd(), ss->dz[j2]), iq.x);
	if (!(flags & FLAG_INIT0)) {
		t1 = _mm_add_sd(t1, _mm_load_sd((double *)tmp + 1));
	}
	int32_t z1 = sampler_next_sse2(ss, t1, leaf);
	ss->dz[j2] = (int16_t)z1;
	if (!(flags & FLAG_NOOUT)) {
		_mm_store_sd((double *)tmp + 1, _mm_sub_sd(t1,
			_mm_cvtsi32_sd(_mm_setzero_pd(), z1)));
	}
#elif FNDSA_NEON
	/* n = 2
	   t = t0 + t1*X; FFT is t0(i) = t0 + t1*i (already split).
	   a = a0  (since a is self-adjoint)  */
	float64x1_t a0 = vld1_f64((const float64_t *)tmp + 2);
	float64x1_t leaf = vmul_f64(vsqrt_f64(a0),
		vld1_f64((const float64_t *)INV_SIGMA + ss->logn));

	/* Elements of dz[] are explored by pairs; base offset
	   is the bit-reversal of a decrementing counter. */
	unsigned j = -- ss->off;
	j = ((j & 0x1C0) >> 6) | (j & 0x038) | ((j & 0x007) << 6);
	j = ((j & 0x124) >> 2) | (j & 0x092) | ((j & 0x049) << 2);
	j >>= (10 - ss->logn);
	unsigned j2 = j + (1u << (ss->logn - 1));

	static const union { fpr f; float64x1_t x; } iq = { FPR_IQ };
	float64x1_t t0 = vmul_f64(vcvt_f64_s64(vcreate_s64(ss->dz[j])), iq.x);
	if (!(flags & FLAG_INIT0)) {
		t0 = vadd_f64(t0, vld1_f64((float64_t *)tmp));
	}
	int32_t z0 = sampler_next_neon(ss, t0, leaf);
	ss->dz[j] = (int16_t)z0;
	if (!(flags & FLAG_NOOUT)) {
		vst1_f64((float64_t *)tmp,
			vsub_f64(t0, vcvt_f64_s64(vcreate_s64(z0))));
	}

	float64x1_t t1 = vmul_f64(vcvt_f64_s64(vcreate_s64(ss->dz[j2])), iq.x);
	if (!(flags & FLAG_INIT0)) {
		t1 = vadd_f64(t1, vld1_f64((float64_t *)tmp + 1));
	}
	int32_t z1 = sampler_next_neon(ss, t1, leaf);
	ss->dz[j2] = (int16_t)z1;
	if (!(flags & FLAG_NOOUT)) {
		vst1_f64((float64_t *)tmp + 1,
			vsub_f64(t1, vcvt_f64_s64(vcreate_s64(z1))));
	}
#elif FNDSA_RV64D
	/* n = 2
	   t = t0 + t1*X; FFT is t0(i) = t0 + t1*i (already split).
	   a = a0  (since a is self-adjoint)  */
	f64 *ttmp = (f64 *)tmp;
	f64 a0 = ttmp[2];
	f64 leaf = f64_mul(f64_sqrt(a0), INV_SIGMA[ss->logn].v);

	/* Elements of dz[] are explored by pairs; base offset
	   is the bit-reversal of a decrementing counter. */
	unsigned j = -- ss->off;
	j = ((j & 0x1C0) >> 6) | (j & 0x038) | ((j & 0x007) << 6);
	j = ((j & 0x124) >> 2) | (j & 0x092) | ((j & 0x049) << 2);
	j >>= (10 - ss->logn);
	unsigned j2 = j + (1u << (ss->logn - 1));

	static const fpr_u xiq = { FPR_IQ };
	f64 t0 = f64_mul(f64_of32(ss->dz[j]), xiq.v);
	if (!(flags & FLAG_INIT0)) {
		t0 = f64_add(t0, ttmp[0]);
	}
	int32_t z0 = sampler_next_rv64d(ss, t0, leaf);
	ss->dz[j] = (int16_t)z0;
	if (!(flags & FLAG_NOOUT)) {
		ttmp[0] = f64_sub(t0, f64_of32(z0));
	}

	f64 t1 = f64_mul(f64_of32(ss->dz[j2]), xiq.v);
	if (!(flags & FLAG_INIT0)) {
		t1 = f64_add(t1, ttmp[1]);
	}
	int32_t z1 = sampler_next_rv64d(ss, t1, leaf);
	ss->dz[j2] = (int16_t)z1;
	if (!(flags & FLAG_NOOUT)) {
		ttmp[1] = f64_sub(t1, f64_of32(z1));
	}
#else
	/* n = 2
	   t = t0 + t1*X; FFT is t0(i) = t0 + t1*i (already split).
	   a = a0  (since a is self-adjoint)  */
	fpr a0 = tmp[2];
	fpr leaf = fpr_mul(fpr_sqrt(a0), INV_SIGMA[ss->logn].f);

	/* Elements of dz[] are explored by pairs; base offset
	   is the bit-reversal of a decrementing counter. */
	unsigned j = -- ss->off;
	j = ((j & 0x1C0) >> 6) | (j & 0x038) | ((j & 0x007) << 6);
	j = ((j & 0x124) >> 2) | (j & 0x092) | ((j & 0x049) << 2);
	j >>= (10 - ss->logn);
	unsigned j2 = j + (1u << (ss->logn - 1));

	fpr t0 = fpr_mul(fpr_of32(ss->dz[j]), FPR_IQ);
	if (!(flags & FLAG_INIT0)) {
		t0 = fpr_add(t0, tmp[0]);
	}
	int32_t z0 = sampler_next(ss, t0, leaf);
	ss->dz[j] = (int16_t)z0;
	if (!(flags & FLAG_NOOUT)) {
		tmp[0] = fpr_sub(t0, fpr_of32(z0));
	}

	fpr t1 = fpr_mul(fpr_of32(ss->dz[j2]), FPR_IQ);
	if (!(flags & FLAG_INIT0)) {
		t1 = fpr_add(t1, tmp[1]);
	}
	int32_t z1 = sampler_next(ss, t1, leaf);
	ss->dz[j2] = (int16_t)z1;
	if (!(flags & FLAG_NOOUT)) {
		tmp[1] = fpr_sub(t1, fpr_of32(z1));
	}
#endif
}

#if FNDSA_ASM_CORTEXM4
#define ffsamp_fft_inner   fndsa_ffsamp_fft_inner
void ffsamp_fft_inner(sampler_state *ss,
	unsigned logn, unsigned flags, fpr *tmp);
#else
/* logn    current degree
   init0   non-zero if t == 0 on input
   noout   non-zero if FFT output is not needed
   tmp     work area

   tmp contents on input:
      t    FFT (8*n bytes)
      a    FFT, self-adjoint (4*n bytes)
   tmp contents on output:
      u    FFT (8*n bytes)   (u = t - z, with z the sampled vector)

   If init0 is set, then t is not set on input, and it is implicitly zero.
   If noout is set, then u is not written on output. */
TARGET_SSE2 TARGET_NEON static void
ffsamp_fft_inner(sampler_state *ss, unsigned logn, unsigned flags, fpr *tmp)
{
	/* Input:
	      t           polynomial, FFT, 8*n bytes
	      a           self-adjoint polynomial, FFT, 4*n bytes
	   Output:
	      u = t - z   polynomial, FFT, 8*n bytes
	   Algorithm:
	      (t0, t1) <- split(t)
	      (a0, a1) <- split(a)  (a0 is self-adj, a1 is X-adj)
	      L10 <- adj(a1)/a0  (1/X-adj)
	      b <- a0 - a1*adj(a1)/a0  (self-adj)
	      keep t0 (4*n), a0 (2*n), L10/(X+1) (2*n)
	      u1 <- recursive-call(t1, b)    (u1 = t1 - z1)
	      t0' <- t0 + u1*L10
	      keep t0 - t0' (4*n), u1 (4*n)
	      v0 <- recursive-call(t0, a0)    (v0 = t0' - z0)
	      u0 <- v0 + (t0 - t0')
	      u <- merge(u0, u1)  */

	if (logn == 1) {
		ffsamp_fft_deepest(ss, flags, tmp);
		return;
	}

	size_t n = (size_t)1 << logn;
	size_t hn = n >> 1;
	size_t qn = n >> 2;

	fpr *tmp0 = tmp;
	fpr *tmp4 = tmp0 + hn;
	fpr *tmp6 = tmp4 + qn;
	fpr *tmp8 = tmp4 + hn;
	fpr *tmp12 = tmp8 + hn;
	fpr *tmp14 = tmp12 + qn;

	/* (tmp12, tmp14) <- (a0, a1) = split(a)  (self-adj) */
	fpoly_split_selfadj_fft(logn, tmp12, tmp14, tmp8);

	/* (tmp0, tmp8) <- (t0, t1) = split(t) */
	if (!(flags & FLAG_INIT0)) {
		fpoly_split_fft(logn, tmp0, tmp8);
	}
	memcpy(tmp4, tmp12, qn * sizeof(fpr));

	/* At this point:
	      tmp0    t0  (4*n)  (unset if init0)
	      tmp4    a0  (2*n)
	      tmp6    free  (2*n)
	      tmp8    t1  (4*n)  (unset if init0)
	      tmp12   free  (2*n)
	      tmp14   b1  (2*n)  */

	/* tmp6 <- (X+1)*L10
	   tmp12 <- a0 - a1*adj(a1)/a0 */
	fpoly_LDL_fft(logn - 1, tmp12, tmp6, tmp4, tmp14);

	/* First recursive call. */
	ffsamp_fft_inner(ss, logn - 1, flags & ~FLAG_NOOUT, tmp8);

	/* At this point:
	      tmp0    t0  (4*n)  (unset if init0)
	      tmp4    a0  (2*n)
	      tmp6    L10/(X+1)  (2*n)
	      tmp8    u1  (4*n)
	      tmp12   free  (4*n) */

	/* tmp12 <- a0
	   tmp14 <- L10/(X+1) */
	memcpy(tmp12, tmp4, hn * sizeof(fpr));

	/* tmp4  <- u1 */
	memcpy(tmp4, tmp8, hn * sizeof(fpr));

	/* tmp8  <- t0 */
	if (!(flags & FLAG_INIT0)) {
		memcpy(tmp8, tmp0, hn * sizeof(fpr));
	}

	/* At this point:
	      tmp0    free  (4*n)
	      tmp4    u1  (4*n)
	      tmp8    t0  (4*n)  (unset if init0)
	      tmp12   a0  (2*n)
	      tmp14   L10/(X+1)  (2*n) */

	/* tmp0 <- t0' - t0 = u1*L10 */
	fpoly_mul_iXadj_fft(logn - 1, tmp0, tmp4, tmp14);

	/* tmp8  <- t0' */
	if (flags & FLAG_INIT0) {
		memcpy(tmp8, tmp0, hn * sizeof(fpr));
	} else {
		fpoly_add(logn - 1, tmp8, tmp0);
	}

	/* At this point:
	      tmp0    t0' - t0  (4*n)
	      tmp4    u1  (4*n)
	      tmp8    t0'  (4*n)
	      tmp12   a0  (2*n)  */

	/* Second recursive call. */
	ffsamp_fft_inner(ss, logn - 1, flags & ~FLAG_INIT0, tmp8);

	/* At this point:
	      tmp0    t0' - t0  (4*n)
	      tmp4    u1  (4*n)
	      tmp8    v0  (4*n)
	      tmp12   free  (4*n)  */

	if (!(flags & FLAG_NOOUT)) {
		/* tmp8  <- u0 = v0 - (t0' - t0) */
		fpoly_sub(logn - 1, tmp8, tmp0);

		/* tmp12 <- u1 */
		memcpy(tmp12, tmp4, hn * sizeof(fpr));

		/* tmp0  <- u = merge(u0, u1) */
		fpoly_merge_fft(logn, tmp0, tmp8, tmp12);
	}
}
#endif

/* see sign_inner.h */
void
ffsamp_fft(sampler_state *ss, unsigned flags, fpr *tmp)
{
	ss->off = 1u << (ss->logn - 1);
	ffsamp_fft_inner(ss, ss->logn, flags, tmp);
}

#if FNDSA_SAMPLER_PROTECT
/* ================= SCA-PROTECTED SAMPLERZ (Lin et al., PKC 2025) ================= */
/*
 * Algorithms 5, 6, 7 of "Thorough Power Analysis on Falcon Gaussian Samplers
 * and Practical Countermeasure" (Lin, Zhang, Yu, Wang, You, Xu, Wang, PKC
 * 2025, ePrint 2025/351), ported from ZKNOX-HW-FALCON falcon_sampler_protect.c
 * onto this implementation's primitives (79-bit base sampler table, SHAKE256
 * sampling PRNG, expm_p63, SIGMA_MIN[logn]).
 *
 * Per iteration of the rejection loop:
 *   - Algorithm 5: four independent half-Gaussian samplings whose 18 table
 *     comparisons are kept as an array of bits and summed in a fixed pattern
 *     (no data-dependent accumulation); one of the four is selected by a
 *     random index. The sign bit b is derived from 4 random bits through a
 *     fixed table.
 *   - Algorithm 6/7: the rejection argument x and the BerExp value are
 *     computed for ALL 2 x 19 candidates (both signs, z0 in 0..18); the
 *     candidate actually used is selected by constant-time indexing, so the
 *     power profile of exp() does not depend on (z0, b).
 * Output distribution is the same discrete Gaussian as the plain sampler;
 * the PRNG tape consumption differs (signatures are not byte-identical).
 * Cost: 4 gaussian0 + 38 expm_p63 per iteration instead of 1 + 1.
 * Workspace: FNDSA_SP_WS_LEN bytes in BSS (x and r candidates, BerExp values).
 */

/* z0 * z0 / (2*sigma0^2) for z0 = 0..18 (sigma0 = 1.8205) */
static const fpr_u SP_Z0SQ_INV_2SQRSIGMA0[19] = {
	{ 0 },
	{ 4594603506513722306ULL }, { 4603610705768463298ULL }, { 4608793741173732154ULL },
	{ 4612617905023204290ULL }, { 4615675366023746911ULL }, { 4617800940428473146ULL },
	{ 4620009106706642817ULL }, { 4621625104277945282ULL }, { 4623068905305979298ULL },
	{ 4624682565278487903ULL }, { 4625831450752485245ULL }, { 4626808139683214138ULL },
	{ 4627869758086180326ULL }, { 4629016305961383809ULL }, { 4629974100122847238ULL },
	{ 4630632303532686274ULL }, { 4631332971678643958ULL }, { 4632076104560720290ULL }
};

/* sign selector from 4 random bits: 1 -> z = s - z0 (negative side),
   2 -> z = s + 1 + z0 (positive side); uniform. */
static const uint8_t SP_B_TABLE[16] = {
	2, 1, 1, 2, 2, 1, 1, 2, 2, 1, 1, 2, 2, 1, 1, 2
};

typedef struct {
	fpr x_arr[3][19];      /* Algorithm 6: x for b' in {1,2}, z+ in 0..18 */
	fpr r_arr[3][19];      /* BerExp: reduced argument */
	uint64_t z_arr[2][19]; /* BerExp: ccs*exp(-x) scaled, per candidate */
} sp_workspace;
#define FNDSA_SP_WS_LEN   sizeof(sp_workspace)
static sp_workspace SP_WS;

/* Algorithm 5: half-Gaussian sampling with the 18 comparison results kept
   as an array (values 0 or 1) instead of a running sum. Same 79-bit look-up
   as fndsa_gaussian0_helper(). */
static void
sp_gaussian0(sampler_state *ss, uint8_t *zbits)
{
	static const uint32_t GAUSS0[][3] = {
		{ 1375468055,  6936092,  9176346 },
		{  711562636,  1023934, 15582455 },
		{  289335016,  4826132, 14746371 },
		{   90749601, 12313548, 10843417 },
		{   21676598,  5732767,  9419414 },
		{    3908963, 11171514,  6206010 },
		{     529006, 11146683, 11891888 },
		{      53503, 15610582, 11661180 },
		{       4032,  7095613, 11671091 },
		{        225, 16701698,   407118 },
		{          9,  6787688,  1638204 },
		{          0,  4870085,  8687822 },
		{          0,   111406, 13946073 },
		{          0,     1887, 12017202 },
		{          0,       23, 11452285 },
		{          0,        0,  3689579 },
		{          0,        0,    25354 },
		{          0,        0,      129 }
	};
	uint64_t lo = prng_next_u64(&ss->pc);
	uint32_t hi = prng_next_u16(&ss->pc);
	uint32_t v0 = ((uint32_t)lo >> 1) & 0x00FFFFFF;
	uint32_t v1 = (uint32_t)(lo >> 25) & 0x00FFFFFF;
	uint32_t v2 = (uint32_t)(lo >> 49) | (hi << 15);
	for (size_t i = 0; i < 18; i ++) {
		uint32_t cc;
		cc = (v0 - GAUSS0[i][2]) >> 31;
		cc = (v1 - GAUSS0[i][1] - cc) >> 31;
		cc = (v2 - GAUSS0[i][0] - cc) >> 31;
		/* Hamming-weight balanced encoding of the comparison result:
		   1 (binary 01) if v >= threshold, 2 (binary 10) if v < threshold
		   (the {0,1} -> {1,2} trick of Lin et al.). */
		zbits[i] = (uint8_t)(1 + cc);
	}
}

/* Fixed-pattern sum over the 18 encoded comparisons: z0 = number of rows
   whose threshold is above the sampled value (code 2). */
static int32_t
sp_z0_from_bits(const uint8_t *zbits)
{
	int32_t acc = 0;
	for (size_t i = 0; i < 18; i ++) {
		acc += zbits[i] >> 1;
	}
	return acc;
}

/* Algorithm 6 helper: x[b'][z+] = ((z+ + cbar[b'])^2) * dss - z+^2/(2 sigma0^2) */
static void
sp_compute_x(const fpr *cbar, fpr dss)
{
	for (int bi = 1; bi < 3; bi ++) {
		for (int j = 0; j < 19; j ++) {
			fpr zj = fpr_of32(j);
			SP_WS.x_arr[bi][j] = fpr_sub(
				fpr_mul(fpr_sqr(fpr_add(zj, cbar[bi])), dss),
				SP_Z0SQ_INV_2SQRSIGMA0[j].f);
		}
	}
}

/* Algorithm 7: BerExp for all 38 candidates, then constant-time selection
   of the one designated by (b, z0) and the usual lazy byte comparison. */
static int
sp_ber_exp(sampler_state *ss, fpr ccs, int b, int32_t z0)
{
	for (int bi = 1; bi < 3; bi ++) {
		for (int j = 0; j < 19; j ++) {
			fpr x = SP_WS.x_arr[bi][j];
			int32_t si = (int32_t)fpr_trunc(fpr_mul(x, INV_LOG2));
			fpr r = fpr_sub(x, fpr_mul(fpr_of32(si), LOG2));
			uint32_t sv = (uint32_t)si;
			sv |= (uint32_t)(63 - sv) >> 26;
			sv &= 63;
			SP_WS.r_arr[bi][j] = r;
			SP_WS.z_arr[bi - 1][j] =
				fpr_ursh((expm_p63(r, ccs) << 1) - 1, sv);
		}
	}
	/* Constant-time selection of z_arr[b-1][z0]. */
	uint64_t zsel = 0;
	for (int bi = 0; bi < 2; bi ++) {
		for (int j = 0; j < 19; j ++) {
			uint64_t m = -(uint64_t)((bi == (b - 1)) & (j == z0));
			zsel |= SP_WS.z_arr[bi][j] & m;
		}
	}
	for (int i = 56; i >= 0; i -= 8) {
		unsigned w = prng_next_u8(&ss->pc);
		unsigned bz = (unsigned)(zsel >> i) & 0xFF;
		if (w != bz) {
			return w < bz;
		}
	}
	return 0;
}

/* Algorithm 6: protected SamplerZ. */
int32_t
sampler_next(sampler_state *ss, fpr mu, fpr isigma)
{
	int64_t s = fpr_floor(mu);
	fpr r = fpr_sub(mu, fpr_of32((int32_t)s));
	fpr cbar[3];
	cbar[0] = 0;
	cbar[1] = r;                          /* candidate z = s - z0 */
	cbar[2] = fpr_sub(fpr_of32(1), r);    /* candidate z = s + 1 + z0 */
	fpr dss = fpr_half(fpr_sqr(isigma));
	fpr ccs = fpr_mul(isigma, SIGMA_MIN[ss->logn].f);

	for (;;) {
		uint8_t zb[4][18];
		int32_t z0c[4];
		int b = SP_B_TABLE[prng_next_u8(&ss->pc) & 0x0F];
		for (int k = 0; k < 4; k ++) {
			sp_gaussian0(ss, zb[k]);
			z0c[k] = sp_z0_from_bits(zb[k]);
		}
		int idx = prng_next_u8(&ss->pc) & 0x03;
		/* constant-time pick of z0c[idx] */
		int32_t z0 = 0;
		for (int k = 0; k < 4; k ++) {
			z0 |= z0c[k] & -(int32_t)(k == idx);
		}
		sp_compute_x(cbar, dss);
		if (sp_ber_exp(ss, ccs, b, z0)) {
			/* b = 1: z = s - z0 ; b = 2: z = s + 1 + z0 (constant-time) */
			int32_t zneg = (int32_t)s - z0;
			int32_t zpos = (int32_t)s + 1 + z0;
			int32_t m = -(int32_t)(b - 1);
			return (zneg & ~m) | (zpos & m);
		}
	}
}
#endif /* FNDSA_SAMPLER_PROTECT */
