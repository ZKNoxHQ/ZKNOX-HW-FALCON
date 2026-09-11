#!/usr/bin/env node
/* falcon1024-full-chain.js — Full Falcon-1024 v0.7.0 closed-loop test.
 *
 *   1. FALCON_KEYGEN  (BIP-32 derived seed, on-device)
 *   2. FALCON_GET_PK  (collect pk h)
 *   3. FALCON_KEYGEN_EXPAND (collect 122864 B wire)
 *   4. Validate pk & wire match references (yellow×12 mnemonic)
 *   5. Pick a 32-B msg digest, choose nonce mode (host or device)
 *   6. FALCON_SIGN    (device computes hash_to_point internally)
 *   7. verify_raw (JS) using nonce + msg + pk
 *
 * USAGE
 *    node falcon1024-full-chain.js [<msg-utf8-or-hex>] [--mode device|host] [--testvec]
 *
 *    Default: msg = "Hello Falcon" (sha256-ed → 32 B), nonceMode = device
 *
 *    --mode host    use host-supplied nonce (random unless --testvec)
 *    --mode device  device tirage TRNG (default)
 *    --testvec      FORCE deterministic mode: nonceMode=host, nonce = 0xAA × 40
 *                   (useful for byte-stable repro across runs)
 */
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const Transport = require('@ledgerhq/hw-transport-node-hid').default;
const { keygenExpand, TOTAL_WIRE_SZ } = require('./falcon1024-ledger-keygen-expand');
const { sign } = require('./falcon1024-ledger-sign');
const { verifyRaw, hashToPoint } = require('./falcon1024-verify');

const CLA = 0xE0;
const INS_KEYGEN = 0x30;
const INS_GET_PK = 0x31;
const SW_OK = 0x9000;

async function sendApdu(t, cla, ins, p1, p2, data) {
    const buf = Buffer.alloc(5 + data.length);
    buf[0] = cla; buf[1] = ins; buf[2] = p1; buf[3] = p2; buf[4] = data.length;
    data.copy(buf, 5);
    const r = await t.exchange(buf);
    return { data: r.slice(0, r.length - 2),
             sw:   (r[r.length - 2] << 8) | r[r.length - 1] };
}

async function deviceKeygenAndPk(transport) {
    let res = await sendApdu(transport, CLA, INS_KEYGEN, 0, 0, Buffer.alloc(0));
    if (res.sw !== SW_OK) throw new Error(`FALCON_KEYGEN: SW=${res.sw.toString(16)}`);
    let pk = res.data;
    for (let i = 1; pk.length < 2048; i++) {
        res = await sendApdu(transport, CLA, INS_GET_PK, i, 0, Buffer.alloc(0));
        if (res.sw !== SW_OK) throw new Error(`FALCON_GET_PK[${i}]: SW=${res.sw.toString(16)}`);
        pk = Buffer.concat([pk, res.data]);
    }
    return pk;
}

function parseArgs() {
    const a = process.argv.slice(2);
    let msg = null;
    let mode = 'device';
    let testvec = false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] === '--mode') { mode = a[++i]; continue; }
        if (a[i] === '--testvec') { testvec = true; continue; }
        if (msg === null) msg = a[i];
    }
    if (msg === null) msg = 'Hello Falcon';
    return { msg, mode, testvec };
}

async function main() {
    const { msg: msgArg, mode: modeArg, testvec } = parseArgs();

    /* The device expects a 32-B digest as the message. Hash the user's input. */
    const msgInputBuf = Buffer.from(msgArg, 'utf8');
    const msgDigest = crypto.createHash('sha256').update(msgInputBuf).digest();

    let nonceMode = modeArg;
    let nonceForHost = undefined;
    if (testvec) {
        nonceMode = 'host';
        nonceForHost = Buffer.alloc(40, 0xAA);
    } else if (nonceMode === 'host') {
        nonceForHost = crypto.randomBytes(40);
    }

    console.log('═══ Falcon-1024 v0.7.0 full-chain test ═══');
    console.log(`message:     "${msgArg}" (${msgInputBuf.length} B utf-8)`);
    console.log(`msg digest:  sha256=${msgDigest.toString('hex')}`);
    console.log(`nonce mode:  ${nonceMode}${testvec ? ' (testvec)' : ''}`);
    if (nonceMode === 'host') {
        console.log(`nonce:       ${nonceForHost.toString('hex').slice(0, 32)}…`);
    }
    console.log();

    /* References */
    const refWirePath = 'falcon1024_yellow12_wire.bin';
    const refPkPath   = 'falcon1024_yellow12_pk.bin';
    if (!fs.existsSync(refWirePath) || !fs.existsSync(refPkPath)) {
        console.error('Missing reference files (yellow×12). Need:');
        console.error(`  - ${refWirePath} (122864 B)`);
        console.error(`  - ${refPkPath} (2048 B)`);
        process.exit(1);
    }
    const refWire = fs.readFileSync(refWirePath);
    const refPk = fs.readFileSync(refPkPath);

    const transport = await Transport.create();
    let okPk = false, okWire = false, okSig = false;
    try {
        /* Step 1: KEYGEN + GET_PK */
        console.log('Step 1 — FALCON_KEYGEN + GET_PK:');
        console.time('  duration');
        const pk = await deviceKeygenAndPk(transport);
        console.timeEnd('  duration');
        const pkHash = crypto.createHash('sha256').update(pk).digest('hex');
        console.log(`  pk: ${pk.length} B sha256=${pkHash}`);
        okPk = pk.equals(refPk);
        console.log(`  vs reference: ${okPk ? '✅' : '❌'}`);
        if (!okPk) { console.error('  pk mismatch — aborting'); process.exit(1); }

        /* Step 2: KEYGEN_EXPAND */
        console.log('\nStep 2 — FALCON_KEYGEN_EXPAND:');
        console.time('  duration');
        const { wire, apduCount: keApdus, timingMs: keT } =
            await keygenExpand(transport);
        console.timeEnd('  duration');
        const wireHash = crypto.createHash('sha256').update(wire).digest('hex');
        console.log(`  wire: ${wire.length} B in ${keApdus} APDUs sha256=${wireHash}`);
        console.log(`  timing: compute_l0=${keT.compute_l0}ms ` +
                    `right=${keT.right_stream}ms left=${keT.left_stream}ms`);
        okWire = wire.equals(refWire);
        console.log(`  vs reference: ${okWire ? '✅' : '❌'}`);
        if (!okWire) { console.error('  wire mismatch — aborting'); process.exit(1); }

        /* Step 3: FALCON_SIGN with on-device hash_to_point */
        console.log(`\nStep 3 — FALCON_SIGN (device hash_to_point, mode=${nonceMode}):`);
        console.time('  duration');
        const { sig, nonce, apduCount: signApdus, timingMs: sT } =
            await sign(transport, msgDigest, wire,
                       { nonceMode, nonce: nonceForHost });
        console.timeEnd('  duration');
        const sigHash = crypto.createHash('sha256').update(sig).digest('hex');
        console.log(`  sig: ${sig.length} B in ${signApdus} APDUs sha256=${sigHash}`);
        console.log(`  nonce used: ${nonce.toString('hex').slice(0, 32)}…`);
        console.log(`  timing: hm=${sT.hm}ms target=${sT.compute_target}ms ` +
                    `right=${sT.right}ms left=${sT.left}ms`);

        /* Step 4: verify_raw in JS */
        console.log('\nStep 4 — verify_raw (JS):');
        const hm = hashToPoint(nonce, msgDigest);
        console.log(`  reconstructed hm sha256=${crypto.createHash('sha256').update(hm).digest('hex')}`);
        console.time('  duration');
        okSig = verifyRaw(hm, sig, pk);
        console.timeEnd('  duration');
        console.log(`  result: ${okSig ? '✅ VALID' : '❌ INVALID'}`);

        console.log();
        if (okPk && okWire && okSig) {
            console.log('═══ ✅ FULL CHAIN PASSED ═══');
            console.log('   keygen + keygen_expand + sign (on-device hash_to_point) + verify');
            console.log('   are all consistent end-to-end.');
        } else {
            console.log('═══ ❌ FAILURE ═══');
            console.log(`  pk:  ${okPk  ? '✅' : '❌'}`);
            console.log(`  wire:${okWire ? '✅' : '❌'}`);
            console.log(`  sig: ${okSig ? '✅' : '❌'}`);
        }
    } finally {
        await transport.close();
    }
    process.exit((okPk && okWire && okSig) ? 0 : 1);
}

main().catch(e => { console.error(e); process.exit(1); });
