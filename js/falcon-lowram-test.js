#!/usr/bin/env node
/*
 * falcon-lowram-test.js — device test of the low-RAM Falcon core through @zknox/hw-app-falcon.
 *
 * Flow per run: key (KEYGEN / GET_PK) -> N signatures (INIT, FEED_MSG, GEN_SEED|FEED_SEED, SIGN_ALL,
 *               GET_NONCE, GET_SIG) -> verify_raw on the host (falcon512-verify.js / falcon1024-verify.js).
 *
 * USAGE
 *   node falcon-lowram-test.js [logn] [count] [--seeded] [--force-keygen]
 *     logn           9 (Falcon-512) or 10 (Falcon-1024, default)
 *     count          signatures to run (default 3)
 *     --seeded       deterministic signatures (fixed 40-byte seeds): two runs give byte-identical signatures
 *     --force-keygen KEYGEN P1=1, recompute the key even if it is already in RAM (measures the keygen)
 *   FALCON_MOCK=1    run against the in-memory mock transport (no device; signatures are not valid)
 *
 * Timings are wall-clock per APDU (USB round trips included).
 */
'use strict';
const crypto = require('crypto');
const FalconApp = require('@zknox/hw-app-falcon');

(async () => {
    const args = process.argv.slice(2);
    const nums = args.filter(a => /^\d+$/.test(a));
    const logn = parseInt(nums[0] || '10', 10);
    const count = parseInt(nums[1] || '3', 10);
    const seeded = args.includes('--seeded');
    const forceKeygen = args.includes('--force-keygen');
    const n = 1 << logn;
    const verify = logn === 9 ? require('./falcon512-verify.js') : require('./falcon1024-verify.js');

    let transport;
    if (process.env.FALCON_MOCK) {
        const MockTransport = require('./hw-app-falcon/test/mock-transport');
        const h = Buffer.alloc(2 * n), s2Raw = Buffer.alloc(2 * n);
        transport = new MockTransport({ logn, h, salt: Buffer.alloc(40), s2Raw });
    } else {
        transport = await require('@ledgerhq/hw-transport-node-hid').default.create();
    }
    const app = new FalconApp(transport);
    console.log(`Falcon-${n} (low-RAM core)`);

    const kg = await app.generateKey({ logn, force: forceKeygen });
    console.log(`KEYGEN${forceKeygen ? ' (forced)' : ''}: ${kg.ms} ms` + (forceKeygen ? '' : ' (first call of the session computes the key, later calls take milliseconds)'));
    const pk = await app.getPublicKey({ logn });
    console.log(`pk (raw h, ${pk.h.length} B) sha256 = ${crypto.createHash('sha256').update(pk.h).digest('hex')}`);

    for (let it = 0; it < count; it++) {
        const msg = crypto.createHash('sha256').update(`falcon-core-test ${it}`).digest();
        const sig = await app.signHash({ logn, hash: msg, seed: seeded ? Buffer.alloc(40, 0xA0 + it) : undefined });
        const hm = verify.hashToPoint(sig.salt, msg);
        const ok = verify.verifyRaw(hm, sig.s2Raw, pk.h);
        console.log(`sig ${it}: SIGN_ALL ${sig.timings.signMs} ms, total ${sig.timings.totalMs} ms, verify_raw ${ok ? 'VALID' : 'INVALID'}` +
                    (seeded ? `, sha256 ${crypto.createHash('sha256').update(sig.s2Raw).digest('hex').slice(0, 16)}…` : ''));
        if (!ok && !process.env.FALCON_MOCK) process.exitCode = 1;
    }
    if (typeof transport.close === 'function') await transport.close();
})().catch(e => { console.error(e.message); process.exit(1); });
