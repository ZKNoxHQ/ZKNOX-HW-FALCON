/*
 * falcon1024-flash-ledger.js — APDU helpers for the Falcon-1024 flash variant
 *
 * INS layout mirrors Falcon-512 flash but at 0x70-0x75. P1 sub-codes for
 * SIGN are identical: 0x00 INIT / 0x06 FEED_MSG / 0x08 FEED_NONCE_HOST /
 * 0x09 GEN_NONCE_DEVICE / 0x10 SIGN_ALL / 0x91 GET_NONCE.
 *
 * Sign duration: ~2.5 sec on Nano S+ (vs ~1 sec for Falcon-512 flash).
 * Bump transport timeout accordingly.
 */

const CLA = 0xE0;

const INS = {
    FLASH_KEYGEN:        0x70,
    FLASH_GET_PK:        0x71,
    FLASH_KEYGEN_EXPAND: 0x72,
    FLASH_SIGN:          0x73,
    FLASH_GET_SIG:       0x74,
    FLASH_DUMP_NVM:      0x75,
};

const SIGN_P1 = {
    INIT:               0x00,
    FEED_MSG:           0x06,
    FEED_NONCE_HOST:    0x08,
    GEN_NONCE_DEVICE:   0x09,
    SIGN_ALL:           0x10,
    GET_NONCE:          0x91,
};

async function send(transport, ins, p1, p2, data = Buffer.alloc(0)) {
    return transport.send(CLA, ins, p1, p2, data);
}

async function flashKeygen(transport) {
    return send(transport, INS.FLASH_KEYGEN, 0x00, 0x00);
}

async function flashKeygenExpand(transport) {
    /* Synchronous on-device, takes ~30-60 sec for Falcon-1024.
     * Caller MUST bump transport timeout to >=120 sec. */
    return send(transport, INS.FLASH_KEYGEN_EXPAND, 0x00, 0x00);
}

async function flashGetPk(transport) {
    const total = 2048;   /* Falcon-1024 pk = uint16[1024] */
    const chunks = [];
    for (let i = 0; i * 255 < total; i++) {
        const r = await send(transport, INS.FLASH_GET_PK, i, 0x00);
        chunks.push(r.subarray(0, r.length - 2));
    }
    return Buffer.concat(chunks).subarray(0, total);
}

async function flashDumpNvm(transport) {
    const total = 90112;   /* Falcon-1024 tree NVRAM */
    const chunks = [];
    let chunkIdx = 0;
    while (chunkIdx * 255 < total) {
        const p1 = (chunkIdx >> 8) & 0xff;
        const p2 = chunkIdx & 0xff;
        const r = await send(transport, INS.FLASH_DUMP_NVM, p1, p2);
        chunks.push(r.subarray(0, r.length - 2));
        chunkIdx++;
    }
    return Buffer.concat(chunks).subarray(0, total);
}

async function flashSignInit(transport) {
    return send(transport, INS.FLASH_SIGN, SIGN_P1.INIT, 0x00);
}

async function flashFeedMsg(transport, msg32) {
    if (msg32.length !== 32) throw new Error(`msg must be 32 bytes, got ${msg32.length}`);
    return send(transport, INS.FLASH_SIGN, SIGN_P1.FEED_MSG, 0x00, msg32);
}

async function flashFeedNonceHost(transport, nonce40) {
    if (nonce40.length !== 40) throw new Error(`nonce must be 40 bytes, got ${nonce40.length}`);
    return send(transport, INS.FLASH_SIGN, SIGN_P1.FEED_NONCE_HOST, 0x00, nonce40);
}

async function flashGenNonceDevice(transport) {
    return send(transport, INS.FLASH_SIGN, SIGN_P1.GEN_NONCE_DEVICE, 0x00);
}

async function flashSignAll(transport) {
    /* Synchronous full sign on-device (~2.5 sec on Nano S+). Bump transport
     * timeout to 10+ sec. */
    return send(transport, INS.FLASH_SIGN, SIGN_P1.SIGN_ALL, 0x00);
}

async function flashGetNonce(transport) {
    const r = await send(transport, INS.FLASH_SIGN, SIGN_P1.GET_NONCE, 0x00);
    return r.subarray(0, r.length - 2);
}

async function flashGetSig(transport) {
    const total = 2048;   /* Falcon-1024 sig = int16[1024] */
    const chunks = [];
    for (let i = 0; i * 255 < total; i++) {
        const r = await send(transport, INS.FLASH_GET_SIG, i, 0x00);
        chunks.push(r.subarray(0, r.length - 2));
    }
    return Buffer.concat(chunks).subarray(0, total);
}

module.exports = {
    INS, SIGN_P1,
    flashKeygen, flashKeygenExpand, flashGetPk, flashDumpNvm,
    flashSignInit, flashFeedMsg, flashFeedNonceHost, flashGenNonceDevice,
    flashSignAll, flashGetNonce, flashGetSig,
};
