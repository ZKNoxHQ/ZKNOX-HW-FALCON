/*
 * cx_outsourced.h — Outsourced encrypted-and-authenticated memory primitive.
 *
 * Application-level prototype of what could become a first-class BOLOS
 * primitive (cx_outsourced_*). The device delegates a large working buffer
 * to an untrusted host: every chunk is encrypted under a key derived from
 * device-internal entropy, authenticated with an offset-bound MAC, and
 * verified-then-decrypted on read.
 *
 * Construction (byte-compatible with handler_falcon_sign.c v0.7.0):
 *   tree_key = SHAKE256("falcon-tree-key" || kdf_input, 32)
 *   mac_key  = SHAKE256("falcon-tree-mac" || kdf_input, 32)
 *   record   = ciphertext || tag
 *      ciphertext = plaintext XOR SHAKE256(tree_key || offset_LE8)
 *      tag        = SHAKE256(mac_key || offset_LE8 || ciphertext, 16)
 *
 * The offset binding prevents reordering, replay across sessions, and
 * substitution between users.
 */
#ifndef CX_OUTSOURCED_H
#define CX_OUTSOURCED_H

#include <stdint.h>
#include <stddef.h>

#define CXO_TAG_LEN 16

typedef enum {
    CXO_OK          = 0,
    CXO_TAG_FAIL    = 1,
    CXO_INVALID_ARG = 2,
} cxo_err_t;

typedef struct {
    uint8_t tree_key[32];
    uint8_t mac_key[32];
} cx_outsourced_t;

/* Derive tree_key and mac_key from kdf_input.
 * kdf_input is typically the application's master seed. */
void cx_outsourced_init(cx_outsourced_t *ctx,
                        const uint8_t *kdf_input,
                        size_t kdf_input_len);

/* Encrypt + tag plaintext at the given byte offset.
 * Writes len + CXO_TAG_LEN bytes into out_record:
 *   out_record[0..len)        = ciphertext
 *   out_record[len..len+16)   = tag
 * Caller is responsible for shipping out_record to the host.
 */
void cx_outsourced_write(cx_outsourced_t *ctx,
                         size_t offset,
                         const uint8_t *plaintext, size_t len,
                         uint8_t *out_record);

/* Verify + decrypt a contiguous record (= plaintext_len + CXO_TAG_LEN).
 * Returns CXO_TAG_FAIL on MAC mismatch (plaintext_out content is undefined
 * and MUST NOT be used).
 *
 * Zero-copy: plaintext_out can alias record.
 */
cxo_err_t cx_outsourced_read(cx_outsourced_t *ctx,
                             size_t offset,
                             const uint8_t *record,
                             size_t plaintext_len,
                             uint8_t *plaintext_out);

/* Same as cx_outsourced_read but with ciphertext and tag in separate buffers.
 * Useful when the caller has accumulated them separately during streaming.
 * Decrypts in place over ciphertext_inout. */
cxo_err_t cx_outsourced_read_split(cx_outsourced_t *ctx,
                                   size_t offset,
                                   uint8_t *ciphertext_inout, size_t len,
                                   const uint8_t tag[CXO_TAG_LEN]);

#endif /* CX_OUTSOURCED_H */
