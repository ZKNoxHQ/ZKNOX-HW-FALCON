/*
 * Falcon-1024 seed derivation (v0.6.0+).
 *
 * Path is HARD-CODED so the host can never influence which key the
 * device produces:
 *
 *     m / 44' / 9004' / 0' / 0 / 0
 *
 * Domain separation via HMAC modifier "Falcon-1024 seed". 9004' is the
 * SLIP-44 coin type ZKNOX uses for Falcon-derived keys.
 */
#include "os.h"
#include "cx.h"
#include <string.h>

#define FALCON_BIP32_PATH_LEN  5
static const uint32_t falcon_bip32_path[FALCON_BIP32_PATH_LEN] = {
    44u, 9004u, 0u, 0u, 0u
};

cx_err_t falcon_derive_seed(uint8_t falcon_seed[32]) {
    static const uint8_t modifier[] = "Falcon-1024 seed";
    uint8_t chaincode[32];
    uint32_t hardened_path[FALCON_BIP32_PATH_LEN];
    cx_err_t err = CX_OK;

    for (size_t i = 0; i < FALCON_BIP32_PATH_LEN; i++) {
        hardened_path[i] = falcon_bip32_path[i] | 0x80000000u;
    }

    os_perso_derive_node_with_seed_key(HDW_ED25519_SLIP10,
                                       CX_CURVE_Ed25519,
                                       hardened_path,
                                       FALCON_BIP32_PATH_LEN,
                                       falcon_seed,
                                       chaincode,
                                       (unsigned char *) modifier,
                                       sizeof(modifier) - 1);

    explicit_bzero(chaincode, sizeof(chaincode));
    explicit_bzero(hardened_path, sizeof(hardened_path));

    return err;
}

/* Same path, modifier "Falcon-512 seed": the Falcon-512 key is independent
 * from the Falcon-1024 one. */
cx_err_t falcon512_derive_seed(uint8_t falcon_seed[32]) {
    static const uint8_t modifier[] = "Falcon-512 seed";
    uint8_t chaincode[32];
    uint32_t hardened_path[FALCON_BIP32_PATH_LEN];
    cx_err_t err = CX_OK;

    for (size_t i = 0; i < FALCON_BIP32_PATH_LEN; i++) {
        hardened_path[i] = falcon_bip32_path[i] | 0x80000000u;
    }
    os_perso_derive_node_with_seed_key(HDW_ED25519_SLIP10,
                                       CX_CURVE_Ed25519,
                                       hardened_path,
                                       FALCON_BIP32_PATH_LEN,
                                       falcon_seed,
                                       chaincode,
                                       (unsigned char *) modifier,
                                       sizeof(modifier) - 1);
    explicit_bzero(chaincode, sizeof(chaincode));
    explicit_bzero(hardened_path, sizeof(hardened_path));
    return err;
}
