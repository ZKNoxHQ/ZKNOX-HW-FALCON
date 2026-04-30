#!/usr/bin/env node
/*
 * falcon1024-compliance-simple.js — v0.6.0 device compliance, simple variant.
 *
 * Same as falcon1024-compliance.js but with NO C-sim dependency. Uses a
 * pre-generated reference wire (falcon1024_yellow12_wire.bin) committed
 * to the repo as the oracle. Build the C sim once, generate the
 * reference, never need gcc again.
 *
 * Drives the device through FALCON_KEYGEN + FALCON_KEYGEN_EXPAND, collects
 * the wire, byte-compares against the committed reference.
 *
 * USAGE
 *   node falcon1024-compliance-simple.js
 *   node falcon1024-compliance-simple.js path/to/wire.bin     # custom ref
 *
 * The default reference assumes the device is configured with the
 * "yellow×12" test mnemonic, no passphrase. If you swap the device
 * mnemonic, regenerate the reference with the C sim once and replace
 * falcon1024_yellow12_wire.bin.
 */
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const Transport = require('@ledgerhq/hw-transport-node-hid').default;
const { keygenExpand, TOTAL_WIRE_SZ } = require('./falcon1024-ledger-keygen-expand');

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

async function devicePullPk(transport) {
    let res = await sendApdu(transport, CLA, INS_KEYGEN, 0, 0, Buffer.alloc(0));
    if (res.sw !== SW_OK)
        throw new Error(`FALCON_KEYGEN failed: sw=${res.sw.toString(16)}`);
    let pk = res.data;
    for (let i = 1; pk.length < 2048; i++) {
        res = await sendApdu(transport, CLA, INS_GET_PK, i, 0, Buffer.alloc(0));
        if (res.sw !== SW_OK)
            throw new Error(`FALCON_GET_PK[${i}] failed: sw=${res.sw.toString(16)}`);
        pk = Buffer.concat([pk, res.data]);
    }
    return pk;
}

async function main() {
    const wireRefPath = process.argv[2] || 'falcon1024_yellow12_wire.bin';
    const pkRefPath   = process.argv[3] || 'falcon1024_yellow12_pk.bin';
    if (!fs.existsSync(wireRefPath)) {
        console.error(`Wire reference not found: ${wireRefPath}`);
        process.exit(1);
    }
    const expectedWire = fs.readFileSync(wireRefPath);
    if (expectedWire.length !== TOTAL_WIRE_SZ) {
        console.error(`Wire reference size: ${expectedWire.length} vs ${TOTAL_WIRE_SZ}`);
        process.exit(1);
    }
    let expectedPk = null;
    if (fs.existsSync(pkRefPath)) {
        expectedPk = fs.readFileSync(pkRefPath);
        if (expectedPk.length !== 2048) {
            console.error(`Pk reference size: ${expectedPk.length} vs 2048`);
            process.exit(1);
        }
    }
    const wireHash = crypto.createHash('sha256').update(expectedWire).digest('hex');
    const pkHash = expectedPk ? crypto.createHash('sha256').update(expectedPk).digest('hex') : null;

    console.log(`Reference wire: ${wireRefPath}  sha256=${wireHash}`);
    if (expectedPk) console.log(`Reference pk:   ${pkRefPath}  sha256=${pkHash}`);
    console.log('  (assumes device mnemonic = "yellow×12", no passphrase)\n');

    const transport = await Transport.create();
    let pkOk = false, wireOk = false;
    try {
        console.time('  FALCON_KEYGEN + GET_PK');
        const pk = await devicePullPk(transport);
        console.timeEnd('  FALCON_KEYGEN + GET_PK');
        const devPkHash = crypto.createHash('sha256').update(pk).digest('hex');
        console.log(`  pk:   ${pk.length} B  sha256=${devPkHash}`);
        if (expectedPk) {
            pkOk = pk.equals(expectedPk);
            console.log(`        vs reference: ${pkOk ? '✅ MATCH' : '❌ DIFFER'}`);
            if (!pkOk) {
                for (let i = 0; i < pk.length; i++) {
                    if (pk[i] !== expectedPk[i]) {
                        console.log(`        first diff at byte ${i}: ` +
                            `dev=${pk[i].toString(16).padStart(2, '0')} ` +
                            `exp=${expectedPk[i].toString(16).padStart(2, '0')}`);
                        break;
                    }
                }
                console.log('  → If pk differs, the BIP-32 derivation is wrong (device seed');
                console.log('    differs from the JS-derived one). Most likely either:');
                console.log('     - device not configured with yellow×12 mnemonic');
                console.log('     - device build is not v0.6.0 (no falcon_derive_seed call)');
                console.log('     - path or modifier mismatch in falcon_derive_seed()');
                fs.writeFileSync('device_pk.bin', pk);
                console.log('  wrote device_pk.bin for offline diff');
            }
        } else {
            pkOk = true;  // no reference → don't gate on it
        }

        console.time('  FALCON_KEYGEN_EXPAND');
        const { wire, apduCount, timingMs } = await keygenExpand(transport);
        console.timeEnd('  FALCON_KEYGEN_EXPAND');
        const devWireHash = crypto.createHash('sha256').update(wire).digest('hex');
        console.log(`  wire: ${wire.length} B in ${apduCount} APDUs  sha256=${devWireHash}`);
        console.log(`  timing: compute_l0=${timingMs.compute_l0}ms ` +
            `right=${timingMs.right_stream}ms left=${timingMs.left_stream}ms`);

        wireOk = wire.equals(expectedWire);
        console.log();
        if (wireOk && pkOk) {
            console.log('  ✅ device pk = ref pk AND device wire = ref wire (byte-identical)');
            console.log('     → BIP-32 derivation + Falcon keygen + streaming-expand');
            console.log('       are all consistent end-to-end.');
        } else if (!wireOk) {
            console.log('  ❌ wire DIVERGENCE');
            const L0_END = 8208, RIGHT_END = L0_END + 57328;
            for (let i = 0; i < wire.length; i++) {
                if (wire[i] !== expectedWire[i]) {
                    const region = i < L0_END ? 'L0'
                                 : i < RIGHT_END ? 'RIGHT'
                                 : 'LEFT';
                    console.log(`  first diff at byte ${i} (${region}): ` +
                        `dev=${wire[i].toString(16).padStart(2, '0')} ` +
                        `exp=${expectedWire[i].toString(16).padStart(2, '0')}`);
                    if (region === 'L0' && i < 32 && pkOk) {
                        console.log('  → pk matched but L0 ciphertext differs from byte 0:');
                        console.log('    streaming-expand has a bug (Gram or LDLmv).');
                    } else if (region === 'L0') {
                        console.log('  → L0 ciphertext differs in mid/late bytes:');
                        console.log('    likely a Gram/LDLmv compute issue.');
                    } else if (region === 'RIGHT' && i === 8208) {
                        console.log('  → divergence at byte 8208 (right subtree start):');
                        console.log('    likely L0 tag overflow bug. Verify kctx.l0_tag is');
                        console.log('    staged out-of-slot in handler_falcon_keygen_expand.c.');
                    } else {
                        console.log('  → tree node divergence at depth ~' +
                            Math.log2((wire.length - i) / 8 + 1).toFixed(1));
                    }
                    break;
                }
            }
            fs.writeFileSync('device_wire.bin', wire);
            console.log('  wrote device_wire.bin for offline diff vs ' + wireRefPath);
        }
    } finally {
        await transport.close();
    }

    process.exit((pkOk && wireOk) ? 0 : 1);
}

main().catch(e => { console.error(e); process.exit(1); });
