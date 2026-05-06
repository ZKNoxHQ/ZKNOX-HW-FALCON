#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "bip32.h"

#include "constants.h"
#include "tx_types.h"

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,         /// version of the application
    GET_APP_NAME = 0x04,        /// name of the application
    GET_PUBLIC_KEY = 0x05,      /// public key of corresponding BIP32 path
    SIGN_TX = 0x06,             /// sign transaction with BIP32 path
    SIGN_TOKEN_TX = 0x07,       /// sign token transaction with BIP32 path and token address
    PROVIDE_TOKEN_INFO = 0x22,  /// provide dynamic token info via CAL TLV descriptor
    /* Falcon-1024 streaming */
    FALCON_KEYGEN = 0x30,
    FALCON_GET_PK = 0x31,
    FALCON_SIGN = 0x33,
    FALCON_KEYGEN_EXPAND = 0x34,
    /* Falcon-512 streaming (v0.1.0) */
    FALCON512_KEYGEN = 0x40,
    FALCON512_GET_PK = 0x41,
    FALCON512_SIGN = 0x43,
    FALCON512_KEYGEN_EXPAND = 0x44,
    /* Falcon-512 flash variant (v0.2.0) */
    FALCON512_FLASH_KEYGEN        = 0x60,
    FALCON512_FLASH_GET_PK        = 0x61,
    FALCON512_FLASH_KEYGEN_EXPAND = 0x62,
    FALCON512_FLASH_SIGN          = 0x63,
    FALCON512_FLASH_GET_SIG       = 0x64,
    FALCON512_FLASH_DUMP_NVM      = 0x65,
    /* Falcon-1024 flash variant (v0.3.0 — NEW) */
    FALCON1024_FLASH_KEYGEN        = 0x70, /// flash keygen (writes pk to NVRAM)
    FALCON1024_FLASH_GET_PK        = 0x71, /// chunked pk read from NVRAM
    FALCON1024_FLASH_KEYGEN_EXPAND = 0x72, /// LDL expand to NVRAM (90 112 B plaintext)
    FALCON1024_FLASH_SIGN          = 0x73, /// flash sign (P1 same as 0x63)
    FALCON1024_FLASH_GET_SIG       = 0x74, /// chunked sig retrieval (2048 B int16 LE)
    FALCON1024_FLASH_DUMP_NVM      = 0x75  /// chunked NVRAM dump (debugging)
} command_e;

/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,
    STATE_PARSED,
    STATE_APPROVED
} state_e;

/**
 * Enumeration with user request type.
 */
typedef enum {
    CONFIRM_ADDRESS,
    CONFIRM_TRANSACTION,
    CONFIRM_TOKEN_TRANSACTION,
    CONFIRM_BLIND_SIGN_HASH
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[65];
    uint8_t chain_code[32];
} pubkey_ctx_t;

#define TOKEN_ADDRESS_LEN 32

typedef struct {
    const char *ticker;
    uint8_t decimals;
} token_info_t;

typedef struct {
    bool is_token_tx;
    token_info_t token_info;
    uint8_t raw_tx[MAX_TRANSACTION_LEN];
    size_t raw_tx_len;
    transaction_t transaction;
    uint8_t m_hash[32];
    uint8_t signature[MAX_DER_SIG_LEN];
    uint8_t signature_len;
    uint8_t v;
} transaction_ctx_t;

typedef struct {
    state_e state;
    union {
        pubkey_ctx_t pk_info;
        transaction_ctx_t tx_info;
    };
    request_type_e req_type;
    uint32_t bip32_path[MAX_BIP32_PATH];
    uint8_t bip32_path_len;
} global_ctx_t;
