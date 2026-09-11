/* falcon1024-ledger-sign.js — Falcon-1024 streaming sign client (v0.7.0).
 *
 * v0.7.0 changes vs v0.6.x:
 *   - INS_SIGN P1=0x01 FEED_HM is REMOVED (rejected hard).
 *   - hash_to_point now happens ON-DEVICE. Host provides:
 *       (a) a 40-B nonce, either explicitly (FEED_NONCE_HOST = 0x08, test
 *           mode) or implicitly via TRNG (GEN_NONCE_DEVICE = 0x09, prod);
 *       (b) a 32-B message digest (FEED_MSG = 0x06).
 *   - The device runs hash_to_point(nonce || msg) via COMPUTE_HM = 0x07.
 *   - The host can pull the device-generated nonce back via
 *     GET_NONCE = 0x91 (only useful when in 'device' nonce mode).
 *   - parent_t1 is recomputed on-device after right DFS export
 *     (fix from v0.6.0 round-1).
 *
 * APDU protocol (v0.7.0):
 *   P1=0x00 INIT             reset state
 *   P1=0x06 FEED_MSG         32-B msg digest, single APDU
 *   P1=0x07 P2=0x80 COMPUTE_HM  hash_to_point(nonce || msg) → device hm
 *   P1=0x08 FEED_NONCE_HOST  40-B nonce, single APDU (test mode)
 *   P1=0x09 GEN_NONCE_DEVICE no data, device tirage TRNG (prod mode)
 *   P1=0x91 GET_NONCE        pull 40-B nonce (returns whatever was set)
 *   P1=0x02 P2=0x80 COMPUTE_TARGET   unchanged
 *   P1=0x03 FEED_TREE_STREAM         unchanged
 *   P1=0x04 P2=0/1 FEED_SWAP         unchanged
 *   P1=0x05 P2=idx GET_SWAP          unchanged
 *   P1=0x90 P2=idx GET_SIG           unchanged
 */
'use strict';

const CLA = 0xE0;
const INS_SIGN = 0x33;
const SW_OK = 0x9000;

const FN_BYTES = 1024 * 8;          // 8192
const NODE_MAC_LEN = 16;
const L0_RECORD_SZ = FN_BYTES + NODE_MAC_LEN;       // 8208
const SUBTREE_RECORD_SZ = 57328;
const TOTAL_WIRE_SZ = L0_RECORD_SZ + 2 * SUBTREE_RECORD_SZ;  // 122864
const MSG_BYTES = 32;
const NONCE_BYTES = 40;
const SIG_BYTES = 2048;

async function sendApdu(t, cla, ins, p1, p2, data) {
    const buf = Buffer.alloc(5 + data.length);
    buf[0] = cla; buf[1] = ins; buf[2] = p1; buf[3] = p2; buf[4] = data.length;
    data.copy(buf, 5);
    const r = await t.exchange(buf);
    return { data: r.slice(0, r.length - 2),
             sw:   (r[r.length - 2] << 8) | r[r.length - 1] };
}

function chunks(buf, sz) {
    const c = [];
    for (let i = 0; i < buf.length; i += sz)
        c.push(buf.slice(i, Math.min(i + sz, buf.length)));
    return c;
}

async function feedChunkedSwap(transport, data, label) {
    const ch = chunks(data, 255);
    let last = null;
    for (let i = 0; i < ch.length; i++) {
        const isLast = (i === ch.length - 1) ? 0x01 : 0x00;
        const res = await sendApdu(transport, CLA, INS_SIGN, 0x04, isLast, ch[i]);
        if (res.sw !== SW_OK)
            throw new Error(`${label} chunk ${i}: SW=${res.sw.toString(16)}`);
        last = res;
    }
    return last;
}

async function getSwapData(transport, totalBytes) {
    let data = Buffer.alloc(0);
    for (let idx = 0; data.length < totalBytes; idx++) {
        const res = await sendApdu(transport, CLA, INS_SIGN, 0x05, idx, Buffer.alloc(0));
        if (res.sw !== SW_OK || res.data.length === 0) break;
        data = Buffer.concat([data, res.data]);
    }
    const endIdx = Math.ceil(totalBytes / 255);
    await sendApdu(transport, CLA, INS_SIGN, 0x05, endIdx, Buffer.alloc(0));
    return data;
}

async function feedSubtreeStream(transport, streamBytes, label) {
    const CHUNK = 255;
    let offset = 0;
    let apduCount = 0;
    while (offset < streamBytes.length) {
        const size = Math.min(CHUNK, streamBytes.length - offset);
        const chunk = streamBytes.slice(offset, offset + size);
        const res = await sendApdu(transport, CLA, INS_SIGN, 0x03, 0, chunk);
        apduCount++;
        if (res.sw !== SW_OK)
            throw new Error(`${label} offset ${offset}: SW=${res.sw.toString(16)}`);
        offset += size;
        if (res.data.length > 0 && res.data[0] === 0x01) {
            return { apduCount, bytesSent: offset, doneEarly: true };
        }
    }
    return { apduCount, bytesSent: offset, doneEarly: false };
}

/* ── New v0.7.0 APDU helpers ─────────────────────────────────────── */

async function feedNonceHost(transport, nonce) {
    if (nonce.length !== NONCE_BYTES)
        throw new Error(`nonce must be ${NONCE_BYTES} B, got ${nonce.length}`);
    const res = await sendApdu(transport, CLA, INS_SIGN, 0x08, 0, nonce);
    if (res.sw !== SW_OK)
        throw new Error(`FEED_NONCE_HOST: SW=${res.sw.toString(16)}`);
}

async function genNonceDevice(transport) {
    const res = await sendApdu(transport, CLA, INS_SIGN, 0x09, 0, Buffer.alloc(0));
    if (res.sw !== SW_OK)
        throw new Error(`GEN_NONCE_DEVICE: SW=${res.sw.toString(16)}`);
}

async function feedMsg(transport, msg32) {
    if (msg32.length !== MSG_BYTES)
        throw new Error(`msg must be ${MSG_BYTES} B (digest), got ${msg32.length}`);
    const res = await sendApdu(transport, CLA, INS_SIGN, 0x06, 0, msg32);
    if (res.sw !== SW_OK)
        throw new Error(`FEED_MSG: SW=${res.sw.toString(16)}`);
}

async function computeHm(transport) {
    const res = await sendApdu(transport, CLA, INS_SIGN, 0x07, 0x80, Buffer.alloc(0));
    if (res.sw !== SW_OK)
        throw new Error(`COMPUTE_HM: SW=${res.sw.toString(16)}`);
}

async function getNonce(transport) {
    const res = await sendApdu(transport, CLA, INS_SIGN, 0x91, 0, Buffer.alloc(0));
    if (res.sw !== SW_OK)
        throw new Error(`GET_NONCE: SW=${res.sw.toString(16)}`);
    if (res.data.length !== NONCE_BYTES)
        throw new Error(`GET_NONCE: bad len ${res.data.length}`);
    return res.data;
}

/* ── Full sign flow ──────────────────────────────────────────────── */

/**
 * Drive the device through the full Falcon-1024 sign flow.
 *
 * @param transport     hw-transport-node-hid
 * @param msg32         32-B message digest (Buffer)
 * @param wire          122864 B wire from FALCON_KEYGEN_EXPAND
 * @param opts.nonceMode  'device' (default) or 'host'
 * @param opts.nonce      40-B Buffer, required iff nonceMode='host'
 * @returns { sig, nonce, apduCount, timingMs }
 */
async function sign(transport, msg32, wire, opts = {}) {
    const nonceMode = opts.nonceMode || 'device';
    if (nonceMode !== 'device' && nonceMode !== 'host')
        throw new Error(`bad nonceMode: ${nonceMode}`);
    if (msg32.length !== MSG_BYTES)
        throw new Error(`msg must be ${MSG_BYTES} B (digest)`);
    if (wire.length !== TOTAL_WIRE_SZ)
        throw new Error(`wire size ${wire.length}`);
    if (nonceMode === 'host' && (!opts.nonce || opts.nonce.length !== NONCE_BYTES))
        throw new Error(`nonceMode='host' requires opts.nonce (40 B Buffer)`);

    const t0 = Date.now();
    let apduCount = 0;

    const L0_record    = wire.slice(0, L0_RECORD_SZ);
    const right_recs   = wire.slice(L0_RECORD_SZ, L0_RECORD_SZ + SUBTREE_RECORD_SZ);
    const left_recs    = wire.slice(L0_RECORD_SZ + SUBTREE_RECORD_SZ);

    /* INIT */
    let res = await sendApdu(transport, CLA, INS_SIGN, 0x00, 0, Buffer.alloc(0));
    apduCount++;
    if (res.sw !== SW_OK) throw new Error(`INIT: SW=${res.sw.toString(16)}`);

    /* Provide nonce */
    if (nonceMode === 'host') {
        await feedNonceHost(transport, opts.nonce);
    } else {
        await genNonceDevice(transport);
    }
    apduCount++;

    /* Provide msg */
    await feedMsg(transport, msg32);
    apduCount++;

    /* Pull nonce — useful in 'device' mode (host needs it for verify) */
    const nonce = await getNonce(transport);
    apduCount++;

    /* COMPUTE_HM (hash_to_point on-device) */
    const tHm0 = Date.now();
    await computeHm(transport);
    apduCount++;
    const tHm = Date.now() - tHm0;

    /* COMPUTE_TARGET */
    const tTarget0 = Date.now();
    res = await sendApdu(transport, CLA, INS_SIGN, 0x02, 0x80, Buffer.alloc(0));
    apduCount++;
    if (res.sw !== SW_OK) throw new Error(`COMPUTE_TARGET: SW=${res.sw.toString(16)}`);
    const tTarget = Date.now() - tTarget0;

    /* L0 enter */
    await feedChunkedSwap(transport, L0_record, 'L0_enter');
    apduCount += Math.ceil(L0_RECORD_SZ / 255);

    /* Right subtree */
    const tRight0 = Date.now();
    const r = await feedSubtreeStream(transport, right_recs, 'right');
    apduCount += r.apduCount;
    const tRight = Date.now() - tRight0;

    /* Pull z1_merged (device recomputes parent_t1 internally on completion) */
    const z1_merged = await getSwapData(transport, FN_BYTES);
    apduCount += Math.ceil(FN_BYTES / 255) + 1;

    /* L0 again (after_right) */
    await feedChunkedSwap(transport, L0_record, 'L0_after_right');
    apduCount += Math.ceil(L0_RECORD_SZ / 255);

    /* Left subtree */
    const tLeft0 = Date.now();
    const l = await feedSubtreeStream(transport, left_recs, 'left');
    apduCount += l.apduCount;
    const tLeft = Date.now() - tLeft0;

    /* Pull z0 */
    const z0 = await getSwapData(transport, FN_BYTES);
    apduCount += Math.ceil(FN_BYTES / 255) + 1;

    /* z0 || z1 (s0 pass) */
    const z0z1 = Buffer.concat([z0, z1_merged]);
    await feedChunkedSwap(transport, z0z1, 'z0z1_s0');
    apduCount += Math.ceil(z0z1.length / 255);

    /* z0 || z1 (s1 pass) — final norm check */
    res = await feedChunkedSwap(transport, z0z1, 'z0z1_s1');
    apduCount += Math.ceil(z0z1.length / 255);
    const normOk = res.data.length > 0 && res.data[0] === 0x01;
    if (!normOk) throw new Error('device norm check failed (||s||² > bound)');

    /* Pull sig */
    let sig = Buffer.alloc(0);
    for (let i = 0; sig.length < SIG_BYTES; i++) {
        res = await sendApdu(transport, CLA, INS_SIGN, 0x90, i, Buffer.alloc(0));
        apduCount++;
        if (res.sw !== SW_OK) break;
        sig = Buffer.concat([sig, res.data]);
    }
    if (sig.length !== SIG_BYTES)
        throw new Error(`GET_SIG truncated: ${sig.length}`);

    return {
        sig, nonce, apduCount,
        timingMs: { hm: tHm, compute_target: tTarget, right: tRight, left: tLeft,
                    total: Date.now() - t0 },
    };
}

module.exports = {
    sign, feedNonceHost, genNonceDevice, feedMsg, computeHm, getNonce,
    TOTAL_WIRE_SZ, MSG_BYTES, NONCE_BYTES, SIG_BYTES,
};
