/*
 * fndsa_sysrng.c — BOLOS replacement for c-fn-dsa-alt's sysrng.c.
 *
 * Only the *_seeded_temp() APIs are used by the app (the seed comes from
 * cx_rng_no_throw() in the handler), so this is a safety net for any
 * remaining non-seeded call path: it draws from the secure element TRNG.
 */
#include <stddef.h>
#include <stdint.h>
#include "os.h"
#include "cx.h"
#include "fndsa_inner.h"

/* see fndsa_inner.h */
int
sysrng(void *dst, size_t len)
{
	if (len != 0) {
		cx_rng_no_throw((uint8_t *)dst, len);
	}
	return 1;
}
