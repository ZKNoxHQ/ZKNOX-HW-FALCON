#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "bip32.h"

#include "constants.h"
#include "tx_types.h"

/**
 * Enumeration with expected INS of APDU commands.
 * Falcon-1024-only build: Dilithium / hybrid / Keccak-utility INS removed.
 */
typedef enum {
    GET_VERSION = 0x03,         /// version of the application
    GET_APP_NAME = 0x04,        /// name of the application
    GET_PUBLIC_KEY = 0x05,      /// public key of corresponding BIP32 path
    SIGN_TX = 0x06,             /// sign transaction with BIP32 path
    SIGN_TOKEN_TX = 0x07,       /// sign token transaction with BIP32 path and token address
    PROVIDE_TOKEN_INFO = 0x22,  /// provide dynamic token info via CAL TLV descriptor
    /* Falcon-1024 post-quantum signature */
    FALCON_KEYGEN = 0x30,       /// Falcon keygen (BIP-32 derived seed, no host data)
    FALCON_GET_PK = 0x31,       /// retrieve Falcon public key chunks
    FALCON_SIGN = 0x33,         /// iterative Falcon sign (host-driven)
    FALCON_KEYGEN_EXPAND = 0x34, /// stream v0.4.0 wire blob (ct||tag per node)
    /* c-fn-dsa-alt core (Falcon Round 3), P2 = logn (9 or 10) */
    FALCON_LR_KEYGEN = 0x50,  /// keygen (persistent, idempotent), returns h[0..255)
    FALCON_LR_GET_PK = 0x51,  /// h chunks (uint16 host order)
    FALCON_LR_SIGN = 0x53,    /// P1: 00 INIT, 06 FEED_MSG, 08 FEED_SEED, 09 GEN_SEED, 10 SIGN_ALL, 91 GET_NONCE
    FALCON_LR_GET_SIG = 0x54  /// s2 chunks (int16 host order)
} command_e;

/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,     /// No state
    STATE_PARSED,   /// Transaction data parsed
    STATE_APPROVED  /// Transaction data approved
} state_e;

/**
 * Enumeration with user request type.
 * Falcon-only build: hybrid sign request types removed.
 */
typedef enum {
    CONFIRM_ADDRESS,            /// confirm address derived from public key
    CONFIRM_TRANSACTION,        /// confirm transaction information
    CONFIRM_TOKEN_TRANSACTION,  /// confirm token transaction information
    CONFIRM_BLIND_SIGN_HASH
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[65];  /// format (1), x-coordinate (32), y-coodinate (32)
    uint8_t chain_code[32];      /// for public key derivation
} pubkey_ctx_t;

#define TOKEN_ADDRESS_LEN 32

/**
 * Structure for token information.
 */
typedef struct {
    const char *ticker;  /// token ticker
    uint8_t decimals;    /// number of decimals
} token_info_t;

/**
 * Structure for transaction information context.
 */
typedef struct {
    // Token related
    bool is_token_tx;         /// flag to indicate if this is a token transaction
    token_info_t token_info;  /// token information retrieved using the token address
    // Signature related
    uint8_t raw_tx[MAX_TRANSACTION_LEN];  /// raw transaction serialized
    size_t raw_tx_len;                    /// length of raw transaction
    transaction_t transaction;            /// structured transaction
    uint8_t m_hash[32];                   /// message hash digest
    uint8_t signature[MAX_DER_SIG_LEN];   /// transaction signature encoded in DER
    uint8_t signature_len;                /// length of transaction signature
    uint8_t v;                            /// parity of y-coordinate of R in ECDSA signature
} transaction_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        pubkey_ctx_t pk_info;       /// public key context
        transaction_ctx_t tx_info;  /// transaction context
    };
    request_type_e req_type;              /// user request
    uint32_t bip32_path[MAX_BIP32_PATH];  /// BIP32 path
    uint8_t bip32_path_len;               /// length of BIP32 path
} global_ctx_t;
