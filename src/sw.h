#pragma once
#include "status_words.h"

/**
 * Status word for dynamic token TLV parsing/validation failed.
 */
#define SW_INVALID_DYNAMIC_TOKEN 0xB009

/**
 * Status word for Falcon-1024 streaming tree node MAC verification failure.
 * v0.3.0+: handler_falcon_sign's FEED_TREE_STREAM / FEED_SWAP (L0 auth path)
 * returns this code when a ct||tag record's tag doesn't verify, so the host
 * can distinguish MAC tampering from generic malformed-data errors.
 */
#define SWO_TREE_MAC_FAIL 0xB00A

/**
 * Status word for swap failure
 */
#define SW_SWAP_FAIL 0xC000

/**
 * Application specific swap error code context
 */
typedef enum swap_error_application_specific_code_t {
    SWAP_ERROR_CODE = 0x00,
    SWAP_ERROR_WRONG_TOKEN_INFO = 0x01,
} swap_error_application_specific_code_t;
