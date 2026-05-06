/*
 * falcon512-flash-ledger.js — APDU helpers for the Falcon-512 flash variant
 *
 * Phase 2b additions (real sign):
 *   flashSignInit, flashFeedMsg, flashFeedNonceHost, flashGenNonceDevice,
 *   flashSignAll, flashGetNonce, flashGetSig
 *
 * Phase 2a (kept):
 *   flashKeygen, flashKeygenExpand, flashGetPk, flashDumpNvm
 */

const CLA = 0xE0;

const INS = {
    FLASH_KEYGEN:        0x60,
    FLASH_GET_PK:        0x61,
    FLASH_KEYGEN_EXPAND: 0x62,
    FLASH_SIGN:          0x63,
    FLASH_GET_SIG:       0x64,
    FLASH_DUMP_NVM:      0x65,
};

/* INS 0x63 P1 sub-codes */
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

/* ============================ Phase 2a ============================ */

async function flashKeygen(transport) {
    return send(transport, INS.FLASH_KEYGEN, 0x00, 0x00);
}

async function flashKeygenExpand(transport) {
    /* Synchronous on-device, takes ~10-20 sec. Caller should bump timeout. */
    return send(transport, INS.FLASH_KEYGEN_EXPAND, 0x00, 0x00);
}

async function flashGetPk(transport) {
    const total = 1024;
    const chunks = [];
    for (let i = 0; i * 255 < total; i++) {
        const r = await send(transport, INS.FLASH_GET_PK, i, 0x00);
        chunks.push(r.subarray(0, r.length - 2));   /* strip SW */
    }
    return Buffer.concat(chunks).subarray(0, total);
}

async function flashDumpNvm(transport) {
    const total = 40960;
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

/* ============================ Phase 2b ============================ */

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
    /* Synchronous full sign on-device (~1 sec on Nano S+). Caller may want
     * to bump transport timeout to 5+ sec for safety. */
    return send(transport, INS.FLASH_SIGN, SIGN_P1.SIGN_ALL, 0x00);
}

async function flashGetNonce(transport) {
    const r = await send(transport, INS.FLASH_SIGN, SIGN_P1.GET_NONCE, 0x00);
    return r.subarray(0, r.length - 2);   /* 40 bytes */
}

async function flashGetSig(transport) {
    const total = 1024;
    const chunks = [];
    for (let i = 0; i * 255 < total; i++) {
        const r = await send(transport, INS.FLASH_GET_SIG, i, 0x00);
        chunks.push(r.subarray(0, r.length - 2));
    }
    return Buffer.concat(chunks).subarray(0, total);
}

module.exports = {
    INS,
    SIGN_P1,
    flashKeygen,
    flashKeygenExpand,
    flashGetPk,
    flashDumpNvm,
    flashSignInit,
    flashFeedMsg,
    flashFeedNonceHost,
    flashGenNonceDevice,
    flashSignAll,
    flashGetNonce,
    flashGetSig,
};
