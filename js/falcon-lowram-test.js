#!/usr/bin/env node
/*
 * falcon-lowram-test.js — device test of the low-RAM Falcon core (c-fn-dsa-alt in Falcon mode) (INS 0x50..0x54).
 *
 * Flow per degree: KEYGEN -> GET_PK -> SIGN(INIT, FEED_MSG, GEN_SEED|FEED_SEED, SIGN_ALL)
 *                  -> GET_NONCE -> GET_SIG -> verify_raw (falcon512-verify.js / falcon1024-verify.js)
 *
 * USAGE
 *   node falcon-lowram-test.js [logn] [count] [--seeded]
 *     logn      9 (Falcon-512) or 10 (Falcon-1024, default)
 *     count     signatures to run (default 3)
 *     --seeded  deterministic signatures (FEED_SEED with a fixed 40-byte seed): two runs
 *               on the same device must give byte-identical signatures
 *
 * Timings are wall-clock per APDU (USB HID round trips included).
 */
'use strict';
const crypto = require('crypto');
const Transport = require('@ledgerhq/hw-transport-node-hid').default;

const CLA = 0xE0;
const INS = { KEYGEN: 0x50, GET_PK: 0x51, SIGN: 0x53, GET_SIG: 0x54 };
const P1 = { INIT: 0x00, FEED_MSG: 0x06, FEED_SEED: 0x08, GEN_SEED: 0x09, SIGN_ALL: 0x10, GET_NONCE: 0x91 };
const SW_OK = 0x9000;

async function apdu(t, ins, p1, p2, data = Buffer.alloc(0)) {
    const buf = Buffer.alloc(5 + data.length);
    buf[0] = CLA; buf[1] = ins; buf[2] = p1; buf[3] = p2; buf[4] = data.length; data.copy(buf, 5);
    const t0 = Date.now();
    const r = await t.exchange(buf);
    const sw = (r[r.length - 2] << 8) | r[r.length - 1];
    if (sw !== SW_OK) throw new Error(`INS ${ins.toString(16)} P1 ${p1.toString(16)} failed: sw=${sw.toString(16)}`);
    return { data: r.slice(0, r.length - 2), ms: Date.now() - t0 };
}
async function pull(t, ins, logn, total) {
    let out = Buffer.alloc(0), ms = 0;
    for (let i = 0; out.length < total; i++) { const r = await apdu(t, ins, i, logn); out = Buffer.concat([out, r.data]); ms += r.ms; }
    return { data: out, ms };
}

(async () => {
    const args = process.argv.slice(2);
    const logn = parseInt(args.find(a => /^\d+$/.test(a)) || '10', 10);
    const count = parseInt(args.filter(a => /^\d+$/.test(a))[1] || '3', 10);
    const seeded = args.includes('--seeded');
    const n = 1 << logn;
    const verify = logn === 9 ? require('./falcon512-verify.js') : require('./falcon1024-verify.js');

    const t = await Transport.create();
    console.log(`Falcon-${n} (low-RAM core)`);

    let r = await apdu(t, INS.KEYGEN, 0, logn);
    console.log(`KEYGEN: ${r.ms} ms (idempotent: milliseconds when the key is already in NVM)`);
    const pk = (await pull(t, INS.GET_PK, logn, 2 * n)).data;
    console.log(`pk (raw h, ${pk.length} B) sha256 = ${crypto.createHash('sha256').update(pk).digest('hex')}`);

    for (let it = 0; it < count; it++) {
        const msg = crypto.createHash('sha256').update(`falcon-core-test ${it}`).digest();
        await apdu(t, INS.SIGN, P1.INIT, logn);
        await apdu(t, INS.SIGN, P1.FEED_MSG, logn, msg);
        if (seeded) await apdu(t, INS.SIGN, P1.FEED_SEED, logn, Buffer.alloc(40, 0xA0 + it));
        else await apdu(t, INS.SIGN, P1.GEN_SEED, logn);
        const rs = await apdu(t, INS.SIGN, P1.SIGN_ALL, logn);
        const nonce = (await apdu(t, INS.SIGN, P1.GET_NONCE, logn)).data;
        const sig = await pull(t, INS.GET_SIG, logn, 2 * n);
        const hm = verify.hashToPoint(nonce, msg);
        const ok = verify.verifyRaw(hm, sig.data, pk);
        console.log(`sig ${it}: SIGN_ALL ${rs.ms} ms, GET_SIG ${sig.ms} ms, verify_raw ${ok ? 'VALID' : 'INVALID'}` +
                    (seeded ? `, sha256 ${crypto.createHash('sha256').update(sig.data).digest('hex').slice(0, 16)}…` : ''));
        if (!ok) process.exitCode = 1;
    }
    await t.close();
})().catch(e => { console.error(e.message); process.exit(1); });
