/*
 * Top-level signature generation functions.
 */

#include "fndsa_sign_inner.h"

#define SEEDBUF_LEN   40

/* Make a 40-byte seed (into seedbuf[]) from the provided seed. If seed
   is NULL, then the system RNG is used (if available). Moreover, the
   private key (sign_key_fg) and message representative (mu) are used
   for "hedging" (tolerating a system RNG of poor quality). Returned value
   is 1 on success, 0 on error; an error may be reported if the system RNG
   is used and it reports a failure.

   This is defined as a separate, non-inlined function so that the space
   taken by the SHAKE256 context is reused. */
NOINLINE
static int
make_seedbuf(uint8_t *seedbuf, const uint8_t *sign_key,
	const uint8_t *mu, size_t mu_len, const void *seed, size_t seed_len)
{
	unsigned logn = sign_key[0] & 0x0F;
	unsigned nbits = fg_nbits(logn);

	/* For hedging support, we need the hash of the private key. */
	shake_context sc;
	shake_init(&sc, 256);
	shake_inject(&sc, sign_key + 1, nbits << (logn - 2));
	shake_flip(&sc);
	shake_extract(&sc, seedbuf, SEEDBUF_LEN);

	/* The derived seed is obtained as:
	     SHAKE256(impl_id || SHAKE256(f||g)[40] || mu || seed)[40]
	   We already have SHAKE256(f||g)[40] in seedbuf[].

	   WARNING:
	   --------

	   'impl_id' is an identifier that characterizes the
	   implementation variant: if two implementations do not perform
	   _exactly_ the same floating-point operations in the same
	   order, then they may diverge at some point, even if working
	   on the same private key and same seed. If somebody indeed
	   uses the same private key, same message and same seed in two
	   such implementations, then the divergence may reveal
	   sensitive information on the private key. We want to avoid
	   that, which is why there is an additional 'impl_id'. For the
	   "official" code, impl_id is the empty string; here, we use an
	   arbitrary 8-byte value. If another implementation may futher
	   diverge, then it MUST change the impl_id value here.

	   (Here I am using the implementation date as identifier; the
	   8-byte size is meant to preserve alignment of inputs in SHAKE.) */
	shake_init(&sc, 256);
	shake_inject(&sc, "20260830", 8);
	shake_inject(&sc, seedbuf, SEEDBUF_LEN);
	shake_inject(&sc, mu, mu_len);

	/* We need some entropy. If none was provided, then we use the
	   system RNG. */
	if (seed == NULL) {
		if (!sysrng(seedbuf, SEEDBUF_LEN)) {
			return 0;
		}
		seed = seedbuf;
		seed_len = SEEDBUF_LEN;
	}
	shake_inject(&sc, seed, seed_len);
	shake_flip(&sc);
	shake_extract(&sc, seedbuf, SEEDBUF_LEN);
	return 1;
}

/* Verified properties at this point:
      degree is acceptable
      encoded signing key has the proper size
      signature buffer is large enough to receive the result
      tmp is large enough (but not necessarily aligned)  */
#if FNDSA_ASM_CORTEXM4
#define sign_step1   fndsa_sign_step1
#else
static
#endif
size_t
sign_step1(unsigned logn, const uint8_t *sign_key, const uint8_t *mu,
	const uint8_t *seed, size_t seed_len, uint8_t *sig, void *tmp)
{
	/* Align tmp to a 32-byte boundary. */
	tmp = (void *)(((uintptr_t)tmp + 31) & ~(uintptr_t)31);

	/* We need a signing seed (40 bytes). */
	uint8_t seedbuf[SEEDBUF_LEN];
	if (!make_seedbuf(seedbuf, sign_key, mu, 64, seed, seed_len)) {
		return 0;
	}

	/* Main signing loop. */
	return sign_core(logn, sign_key + 1, mu, 64,
		seedbuf, SEEDBUF_LEN, sig, tmp);

	/* TODO: maybe explicitly overwrite the whole temporary area with
	   zeros? Arguably this is mostly wasted time if the area is
	   allocated on the stack, and if tmp is provided explicitly then
	   it is the responsibility of the caller to do any appropriate
	   zeroizing. */
}

/* Custom wrappers to allocate the temporary buffers on the stack. Several
   wrappers are defined so that stack allocation is not always worst-case. */
#define SIGN_WRAP(sz)   \
	NOINLINE static size_t sign_ ## sz(unsigned logn, \
		const uint8_t *sign_key, const uint8_t *mu, \
		const uint8_t *seed, size_t seed_len, \
		uint8_t *sig) \
	{ \
		uint8_t tmp[(sz) * 20 + 31]; \
		return sign_step1(logn, \
			sign_key, mu, seed, seed_len, sig, tmp); \
	}

SIGN_WRAP(32)
SIGN_WRAP(64)
SIGN_WRAP(128)
SIGN_WRAP(256)
SIGN_WRAP(512)
SIGN_WRAP(1024)

static size_t
sign_wrapper(int weak,
	const uint8_t *sign_key, size_t sign_key_len,
	const uint8_t *ctx, size_t ctx_len,
	const char *id, const uint8_t *hv, size_t hv_len,
	const uint8_t *seed, size_t seed_len,
	uint8_t *sig, size_t max_sig_len,
	void *tmp, size_t tmp_len)
{
	/* Signing key defines the degree to use. */
	if (sign_key_len == 0) {
		return 0;
	}
	unsigned head = sign_key[0];
	if ((head & 0xF0) != 0x50) {
		return 0;
	}
	unsigned logn = head & 0x0F;
	if (weak) {
		if (logn < 2 || logn > 8) {
			return 0;
		}
	} else {
		if (logn < 9 || logn > 10) {
			return 0;
		}
	}
	if (sign_key_len != FNDSA_SIGN_KEY_SIZE(logn)) {
		return 0;
	}
	if (sig == NULL) {
		return FNDSA_SIGNATURE_SIZE(logn);
	}
	if (max_sig_len < FNDSA_SIGNATURE_SIZE(logn)) {
		return 0;
	}

	/* We have checked that the degree is acceptable, the signing key
	   size is correct, and the signature will fit in the output buffer.
	   We compute the message representative mu. */
	uint8_t mu[64];
	if (id != NULL && *(const uint8_t *)id == 0xFE) {
		/* External mu mode. */
		if (hv_len != 64) {
			return 0;
		}
		memcpy(mu, hv, hv_len);
	} else {
		if (!fndsa_compute_mu(mu,
			fndsa_hashed_vrfykey_from_signkey(
				sign_key, sign_key_len),
			ctx, ctx_len, id, hv, hv_len))
		{
			return 0;
		}
	}

	if (tmp == NULL) {
		switch (logn) {
		case 6:
			return sign_64(logn,
				sign_key, mu, seed, seed_len, sig);
		case 7:
			return sign_128(logn,
				sign_key, mu, seed, seed_len, sig);
		case 8:
			return sign_256(logn,
				sign_key, mu, seed, seed_len, sig);
		case 9:
			return sign_512(logn,
				sign_key, mu, seed, seed_len, sig);
		case 10:
			return sign_1024(logn,
				sign_key, mu, seed, seed_len, sig);
		default:
			return sign_32(logn,
				sign_key, mu, seed, seed_len, sig);
		}
	} else {
		if (tmp_len < (((size_t)20 << logn) + 31)) {
			return 0;
		}
		return sign_step1(logn,
			sign_key, mu, seed, seed_len, sig, tmp);
	}
}

/* see fndsa.h */
size_t
fndsa_sign(const void *sign_key, size_t sign_key_len,
	const void *ctx, size_t ctx_len,
	const char *id, const void *hv, size_t hv_len,
	void *sig, size_t max_sig_len)
{
	return sign_wrapper(0, sign_key, sign_key_len,
		ctx, ctx_len, id, hv, hv_len,
		NULL, 0, sig, max_sig_len, NULL, 0);
}

/* see fndsa.h */
size_t
fndsa_sign_seeded(const void *sign_key, size_t sign_key_len,
	const void *ctx, size_t ctx_len,
	const char *id, const void *hv, size_t hv_len,
	const void *seed, size_t seed_len,
	void *sig, size_t max_sig_len)
{
	return sign_wrapper(0, sign_key, sign_key_len,
		ctx, ctx_len, id, hv, hv_len,
		seed, seed_len, sig, max_sig_len, NULL, 0);
}

/* see fndsa.h */
size_t
fndsa_sign_temp(const void *sign_key, size_t sign_key_len,
	const void *ctx, size_t ctx_len,
	const char *id, const void *hv, size_t hv_len,
	void *sig, size_t max_sig_len,
	void *tmp, size_t tmp_len)
{
	return sign_wrapper(0, sign_key, sign_key_len,
		ctx, ctx_len, id, hv, hv_len,
		NULL, 0, sig, max_sig_len, tmp, tmp_len);
}

/* see fndsa.h */
size_t
fndsa_sign_seeded_temp(const void *sign_key, size_t sign_key_len,
	const void *ctx, size_t ctx_len,
	const char *id, const void *hv, size_t hv_len,
	const void *seed, size_t seed_len,
	void *sig, size_t max_sig_len,
	void *tmp, size_t tmp_len)
{
	return sign_wrapper(0, sign_key, sign_key_len,
		ctx, ctx_len, id, hv, hv_len,
		seed, seed_len, sig, max_sig_len, tmp, tmp_len);
}

/* see fndsa.h */
size_t
fndsa_sign_weak(const void *sign_key, size_t sign_key_len,
	const void *ctx, size_t ctx_len,
	const char *id, const void *hv, size_t hv_len,
	void *sig, size_t max_sig_len)
{
	return sign_wrapper(1, sign_key, sign_key_len,
		ctx, ctx_len, id, hv, hv_len,
		NULL, 0, sig, max_sig_len, NULL, 0);
}

/* see fndsa.h */
size_t
fndsa_sign_weak_seeded(const void *sign_key, size_t sign_key_len,
	const void *ctx, size_t ctx_len,
	const char *id, const void *hv, size_t hv_len,
	const void *seed, size_t seed_len,
	void *sig, size_t max_sig_len)
{
	return sign_wrapper(1, sign_key, sign_key_len,
		ctx, ctx_len, id, hv, hv_len,
		seed, seed_len, sig, max_sig_len, NULL, 0);
}

/* see fndsa.h */
size_t
fndsa_sign_weak_temp(const void *sign_key, size_t sign_key_len,
	const void *ctx, size_t ctx_len,
	const char *id, const void *hv, size_t hv_len,
	void *sig, size_t max_sig_len,
	void *tmp, size_t tmp_len)
{
	return sign_wrapper(1, sign_key, sign_key_len,
		ctx, ctx_len, id, hv, hv_len,
		NULL, 0, sig, max_sig_len, tmp, tmp_len);
}

/* see fndsa.h */
size_t
fndsa_sign_weak_seeded_temp(const void *sign_key, size_t sign_key_len,
	const void *ctx, size_t ctx_len,
	const char *id, const void *hv, size_t hv_len,
	const void *seed, size_t seed_len,
	void *sig, size_t max_sig_len,
	void *tmp, size_t tmp_len)
{
	return sign_wrapper(1, sign_key, sign_key_len,
		ctx, ctx_len, id, hv, hv_len,
		seed, seed_len, sig, max_sig_len, tmp, tmp_len);
}

#if FNDSA_FALCON_R3
/*
 * Falcon Round 3 signing entry point (embedded / no OS RNG):
 *   logn         9 or 10
 *   fgF          raw private key: f | g | F, int8, 3n bytes (a Falcon key)
 *   msg, msg_len message: Falcon hashes nonce || msg directly (no mu)
 *   seed         caller-provided entropy (40 bytes recommended), hedged
 *                with the key and the message as in FN-DSA
 *   out          output buffer, at least 41 + 2n bytes:
 *                out[0] = 0x30 + logn, out[1..40] = nonce,
 *                out[41..] = s2 (int16, host order)
 *   tmp          temporary area, at least 20n + 31 bytes
 * Returns 41 + 2n on success, 0 on error.
 */
size_t
fndsa_falcon_sign_seeded_temp(unsigned logn, const int8_t *fgF,
	const void *msg, size_t msg_len, const void *seed, size_t seed_len,
	void *out, size_t out_len, void *tmp, size_t tmp_len)
{
	if (logn < 9 || logn > 10 || seed == NULL) {
		return 0;
	}
	size_t n = (size_t)1 << logn;
	if (out_len < 41 + 2 * n || tmp_len < 20 * n + 31) {
		return 0;
	}
	tmp = (void *)(((uintptr_t)tmp + 31) & ~(uintptr_t)31);

	/* Hedged 40-byte signing seed:
	     SHAKE256("20260830-falcon" || SHAKE256(f||g)[40] || msg || seed)[40]
	   (same construction as make_seedbuf(), raw key, own impl_id). */
	uint8_t seedbuf[SEEDBUF_LEN];
	shake_context sc;
	shake_init(&sc, 256);
	shake_inject(&sc, fgF, 2 * n);
	shake_flip(&sc);
	shake_extract(&sc, seedbuf, SEEDBUF_LEN);
	shake_init(&sc, 256);
	shake_inject(&sc, "20260830-falcon", 15);
	shake_inject(&sc, seedbuf, SEEDBUF_LEN);
	shake_inject(&sc, msg, msg_len);
	shake_inject(&sc, seed, seed_len);
	shake_flip(&sc);
	shake_extract(&sc, seedbuf, SEEDBUF_LEN);

	return sign_core(logn, (const uint8_t *)fgF, msg, msg_len,
		seedbuf, SEEDBUF_LEN, out, tmp);
}
#endif
