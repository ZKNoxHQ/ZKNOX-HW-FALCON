/*
 * cx_outsourced.c — Reference implementation of the outsourced memory
 *                   primitive used by Falcon-1024 LDL tree streaming.
 *
 * Byte-for-byte compatible with the inline crypto previously embedded in
 * handler_falcon_sign.c v0.7.0. Migrating the sign handler to call this
 * module produces the same wire bytes and verifies against the same
 * test vectors.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cx_outsourced.h"
#include "falcon_inner.h"   /* Zf(i_shake256_*) */

/* ── Local helpers ───────────────────────────────────────────────── */

/* 8-byte LE encoding of a byte offset. Upper 4 bytes are always 0 for
 * Falcon-1024 (max cumulative offset ~82 KB << 2^32) but the wire format
 * reserves all 8 bytes for forward compatibility. */
static void off_to_le8(size_t byte_offset, uint8_t off_le[8]) {
    off_le[0] = (uint8_t)(byte_offset);
    off_le[1] = (uint8_t)(byte_offset >> 8);
    off_le[2] = (uint8_t)(byte_offset >> 16);
    off_le[3] = (uint8_t)(byte_offset >> 24);
    off_le[4] = 0; off_le[5] = 0; off_le[6] = 0; off_le[7] = 0;
}

/* Constant-time equality. Used for tag comparison so that timing under
 * a coercing host issuing many forgery attempts does not leak which byte
 * mismatches. */
static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* Stream cipher: data XOR SHAKE256(tree_key || offset_LE8).
 * Symmetric, so used for both encrypt and decrypt. Operates in place. */
static void apply_keystream(const uint8_t key[32],
                            uint8_t *data, size_t len,
                            size_t byte_offset) {
    uint8_t off_le[8];
    off_to_le8(byte_offset, off_le);

    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, key, 32);
    Zf(i_shake256_inject)(&xof, off_le, 8);
    Zf(i_shake256_flip)(&xof);

    uint8_t ks[64];
    size_t pos = 0;
    while (pos < len) {
        size_t c = len - pos;
        if (c > 64) c = 64;
        Zf(i_shake256_extract)(&xof, ks, c);
        for (size_t i = 0; i < c; i++) data[pos + i] ^= ks[i];
        pos += c;
    }
}

/* tag = SHAKE256(mac_key || offset_LE8 || ciphertext, CXO_TAG_LEN).
 * Called with the CIPHERTEXT (not plaintext) so verification runs before
 * any decryption work. */
static void compute_tag(const uint8_t mkey[32],
                        const uint8_t *ciphertext, size_t len,
                        size_t byte_offset,
                        uint8_t tag_out[CXO_TAG_LEN]) {
    uint8_t off_le[8];
    off_to_le8(byte_offset, off_le);

    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, mkey, 32);
    Zf(i_shake256_inject)(&xof, off_le, 8);
    Zf(i_shake256_inject)(&xof, ciphertext, len);
    Zf(i_shake256_flip)(&xof);
    Zf(i_shake256_extract)(&xof, tag_out, CXO_TAG_LEN);
}

/* Domain-separated KDF: out = SHAKE256(label || kdf_input, 32). */
static void derive_subkey(uint8_t out[32],
                          const char *label, size_t label_len,
                          const uint8_t *kdf_input, size_t kdf_input_len) {
    inner_shake256_context xof;
    Zf(i_shake256_init)(&xof);
    Zf(i_shake256_inject)(&xof, (const uint8_t *)label, label_len);
    Zf(i_shake256_inject)(&xof, kdf_input, kdf_input_len);
    Zf(i_shake256_flip)(&xof);
    Zf(i_shake256_extract)(&xof, out, 32);
}

/* ── Public API ──────────────────────────────────────────────────── */

void cx_outsourced_init(cx_outsourced_t *ctx,
                        const uint8_t *kdf_input,
                        size_t kdf_input_len) {
    derive_subkey(ctx->tree_key, "falcon-tree-key", 15,
                  kdf_input, kdf_input_len);
    derive_subkey(ctx->mac_key,  "falcon-tree-mac", 15,
                  kdf_input, kdf_input_len);
}

void cx_outsourced_write(cx_outsourced_t *ctx,
                         size_t offset,
                         const uint8_t *plaintext, size_t len,
                         uint8_t *out_record) {
    if (out_record != plaintext) {
        memcpy(out_record, plaintext, len);
    }
    apply_keystream(ctx->tree_key, out_record, len, offset);
    compute_tag(ctx->mac_key, out_record, len, offset, out_record + len);
}

cxo_err_t cx_outsourced_read(cx_outsourced_t *ctx,
                             size_t offset,
                             const uint8_t *record,
                             size_t plaintext_len,
                             uint8_t *plaintext_out) {
    uint8_t expected_tag[CXO_TAG_LEN];
    compute_tag(ctx->mac_key, record, plaintext_len, offset, expected_tag);

    if (!ct_memeq(expected_tag, record + plaintext_len, CXO_TAG_LEN)) {
        return CXO_TAG_FAIL;
    }

    if (plaintext_out != record) {
        memcpy(plaintext_out, record, plaintext_len);
    }
    apply_keystream(ctx->tree_key, plaintext_out, plaintext_len, offset);

    return CXO_OK;
}

cxo_err_t cx_outsourced_read_split(cx_outsourced_t *ctx,
                                   size_t offset,
                                   uint8_t *ciphertext_inout, size_t len,
                                   const uint8_t tag[CXO_TAG_LEN]) {
    uint8_t expected_tag[CXO_TAG_LEN];
    compute_tag(ctx->mac_key, ciphertext_inout, len, offset, expected_tag);

    if (!ct_memeq(expected_tag, tag, CXO_TAG_LEN)) {
        return CXO_TAG_FAIL;
    }

    apply_keystream(ctx->tree_key, ciphertext_inout, len, offset);

    return CXO_OK;
}
