#!/usr/bin/env node
// falcon512-ledger-keygen-expand.js — v0.5.2 integration
//
// Drives the on-device INS_FALCON_KEYGEN_EXPAND (0x44) handler through
// its 6-phase protocol and collects the 26608 B wire blob.
//
// This matches handler_falcon_keygen_expand.c in the integrated tree:
// the device reads g_zknox.falcon_{seed,f,g,F,G} from its own BSS
// (populated by a prior FALCON_KEYGEN), so we do NOT feed keys over APDU.
//
// Protocol:
//   P1=0x00              COMPUTE_L0     no data, runs Gram + L10 LDL
//   P1=0x01 P2=idx       GET_L0         255 B chunk at offset idx*255
//                                       of the 4112 B L0 record
//   P1=0x02              PREP_RIGHT     no data, splits + walker init
//   P1=0x03              GET_NEXT_R     sequential 255 B chunks of right stream
//   P1=0x04              PREP_LEFT      no data, swap walker to left
//   P1=0x05              GET_NEXT_L     sequential 255 B chunks of left stream
//
// Wire output (26608 B):
//   0      L0 ct                 4096 B
//   4096   L0 tag                  16 B
//   4112   right subtree records 26608 B  (511 nodes with ct||tag)
//   30720  left subtree records  26608 B
//
// Preconditions:
//   - Host must have run FALCON_KEYGEN (0x30) to populate g_zknox.
//   - Host must have pulled the public key via FALCON_GET_PK (0x31)
//     BEFORE calling this handler (expand overwrites _falcon_sign_area
//     where h is staged).
'use strict';
const Transport = require('@ledgerhq/hw-transport-node-hid').default;

const CLA = 0xE0;
const INS_FALCON_KEYGEN_EXPAND = 0x44;

const P1_COMPUTE_L0  = 0x00;
const P1_GET_L0      = 0x01;
const P1_PREP_RIGHT  = 0x02;
const P1_GET_NEXT_R  = 0x03;
const P1_PREP_LEFT   = 0x04;
const P1_GET_NEXT_L  = 0x05;

const SW_OK = 0x9000;

// Wire layout constants (must match handler_falcon_keygen_expand.c)
const FLOGN = 9;
const FN = 1 << FLOGN;
const DFS_LOGN = 8;
const NODE_MAC_LEN = 16;
const L0_RECORD_SZ = FN * 8 + NODE_MAC_LEN;                // 4112
const SUBTREE_NODES = (1 << (DFS_LOGN + 1)) - 1;            // 511
const tsz = (l) => (l + 1) * (1 << l);
const SUBTREE_RECORD_SZ =
    tsz(DFS_LOGN) * 8 + SUBTREE_NODES * NODE_MAC_LEN;        // 26608
const TOTAL_WIRE_SZ = L0_RECORD_SZ + 2 * SUBTREE_RECORD_SZ;  // 57328

async function sendApdu(t, cla, ins, p1, p2, data) {
    const buf = Buffer.alloc(5 + data.length);
    buf[0] = cla; buf[1] = ins; buf[2] = p1; buf[3] = p2; buf[4] = data.length;
    data.copy(buf, 5);
    const r = await t.exchange(buf);
    return { data: r.slice(0, r.length - 2),
             sw:   (r[r.length - 2] << 8) | r[r.length - 1] };
}

/**
 * Drive the keygen-expand protocol on a Ledger device.
 * Assumes g_zknox is already populated by a prior FALCON_KEYGEN.
 *
 * @param transport @ledgerhq hw-transport
 * @returns  { wire: Buffer(122864), apduCount: number, timingMs: object }
 */
async function keygenExpand(transport) {
    const t0 = Date.now();
    let apduCount = 0;
    let res;

    // Phase 1 — COMPUTE_L0 on device (Gram + Level-10 LDL)
    const tCompute0 = Date.now();
    res = await sendApdu(transport, CLA, INS_FALCON_KEYGEN_EXPAND,
                         P1_COMPUTE_L0, 0, Buffer.alloc(0));
    apduCount++;
    if (res.sw !== SW_OK) throw new Error(`COMPUTE_L0 failed: sw=${res.sw.toString(16)}`);
    const tCompute = Date.now() - tCompute0;

    // Phase 2 — GET_L0 by chunk index (random access within the 4112 B record)
    let l0 = Buffer.alloc(0);
    let idx = 0;
    while (l0.length < L0_RECORD_SZ) {
        res = await sendApdu(transport, CLA, INS_FALCON_KEYGEN_EXPAND,
                             P1_GET_L0, idx, Buffer.alloc(0));
        apduCount++;
        if (res.sw !== SW_OK)
            throw new Error(`GET_L0[${idx}] failed: sw=${res.sw.toString(16)}`);
        l0 = Buffer.concat([l0, res.data]);
        idx++;
    }
    if (l0.length !== L0_RECORD_SZ)
        throw new Error(`L0 overshoot: ${l0.length} vs ${L0_RECORD_SZ}`);

    // Phase 3 — PREP_RIGHT (splits + first right-subtree node staged on device)
    res = await sendApdu(transport, CLA, INS_FALCON_KEYGEN_EXPAND,
                         P1_PREP_RIGHT, 0, Buffer.alloc(0));
    apduCount++;
    if (res.sw !== SW_OK) throw new Error(`PREP_RIGHT failed: sw=${res.sw.toString(16)}`);

    // Phase 4 — GET_NEXT_R, sequential pulls until 26608 B collected
    const tRight0 = Date.now();
    let right = Buffer.alloc(0);
    while (right.length < SUBTREE_RECORD_SZ) {
        res = await sendApdu(transport, CLA, INS_FALCON_KEYGEN_EXPAND,
                             P1_GET_NEXT_R, 0, Buffer.alloc(0));
        apduCount++;
        if (res.sw !== SW_OK)
            throw new Error(`GET_NEXT_R @${right.length}: sw=${res.sw.toString(16)}`);
        // Cap at the expected right subtree size — device may over-produce on
        // the boundary node; trim.
        let c = res.data.length;
        if (right.length + c > SUBTREE_RECORD_SZ) c = SUBTREE_RECORD_SZ - right.length;
        right = Buffer.concat([right, res.data.slice(0, c)]);
        if (apduCount % 60 === 0) {
            process.stdout.write(
                `  right: ${right.length}/${SUBTREE_RECORD_SZ} (${apduCount} APDUs)\r`);
        }
    }
    const tRight = Date.now() - tRight0;

    // Phase 5 — PREP_LEFT
    res = await sendApdu(transport, CLA, INS_FALCON_KEYGEN_EXPAND,
                         P1_PREP_LEFT, 0, Buffer.alloc(0));
    apduCount++;
    if (res.sw !== SW_OK) throw new Error(`PREP_LEFT failed: sw=${res.sw.toString(16)}`);

    // Phase 6 — GET_NEXT_L, sequential pulls until another 26608 B collected
    const tLeft0 = Date.now();
    let left = Buffer.alloc(0);
    while (left.length < SUBTREE_RECORD_SZ) {
        res = await sendApdu(transport, CLA, INS_FALCON_KEYGEN_EXPAND,
                             P1_GET_NEXT_L, 0, Buffer.alloc(0));
        apduCount++;
        if (res.sw !== SW_OK)
            throw new Error(`GET_NEXT_L @${left.length}: sw=${res.sw.toString(16)}`);
        let c = res.data.length;
        if (left.length + c > SUBTREE_RECORD_SZ) c = SUBTREE_RECORD_SZ - left.length;
        left = Buffer.concat([left, res.data.slice(0, c)]);
        if (apduCount % 60 === 0) {
            process.stdout.write(
                `  left:  ${left.length}/${SUBTREE_RECORD_SZ} (${apduCount} APDUs)\r`);
        }
    }
    const tLeft = Date.now() - tLeft0;
    process.stdout.write('\n');

    const wire = Buffer.concat([l0, right, left]);
    if (wire.length !== TOTAL_WIRE_SZ)
        throw new Error(`total size mismatch: ${wire.length} vs ${TOTAL_WIRE_SZ}`);

    return {
        wire, apduCount,
        timingMs: { compute_l0: tCompute, right_stream: tRight,
                    left_stream: tLeft, total: Date.now() - t0 },
    };
}

module.exports = { keygenExpand, TOTAL_WIRE_SZ, L0_RECORD_SZ, SUBTREE_RECORD_SZ };

// Standalone harness for v0.6.0 device builds (seed derived on-device).
//
// The host CANNOT pin the device's Falcon seed to a specific value — it
// is derived from BIP-32 path m/44'/9004'/0'/0/0 keyed on the device's
// own master seed. Therefore the v0.5.x testvec JSON (which assumes a
// host-fed seed) cannot be used as-is.
//
// What this harness does instead:
//   1. Run FALCON_KEYGEN (Lc=0) → device derives + populates g_zknox.
//   2. Pull the public key h via FALCON_GET_PK.
//   3. Run FALCON_KEYGEN_EXPAND → collect the 26608 B wire blob.
//   4. (Optional) Sign a message via FALCON_SIGN, verify locally with h.
//
// To check that the wire blob is internally consistent, you can:
//   - Re-run sign on the device using the wire (FEED_SWAP + FEED_TREE_STREAM
//     paths in handler_falcon_sign.c), get a signature, verify it locally.
//   - That's the closed-loop integrity test for v0.6.0.
if (require.main === module) {
    const INS_KEYGEN  = 0x40;
    const INS_GET_PK  = 0x41;

    async function setupKey(transport) {
        // v0.6.0: empty payload, seed derived on-device.
        let res = await sendApdu(transport, CLA, INS_KEYGEN, 0, 0, Buffer.alloc(0));
        if (res.sw !== SW_OK)
            throw new Error(`FALCON_KEYGEN failed: sw=${res.sw.toString(16)}`);
        let pk = res.data;
        for (let i = 1; pk.length < 1024; i++) {
            res = await sendApdu(transport, CLA, INS_GET_PK, i, 0, Buffer.alloc(0));
            if (res.sw !== SW_OK)
                throw new Error(`FALCON_GET_PK[${i}] failed: sw=${res.sw.toString(16)}`);
            pk = Buffer.concat([pk, res.data]);
        }
        return pk;
    }

    (async () => {
        const transport = await Transport.create();
        try {
            console.time('  setupKey (FALCON_KEYGEN + GET_PK)');
            const pk = await setupKey(transport);
            console.timeEnd('  setupKey (FALCON_KEYGEN + GET_PK)');
            console.log(`  pk: ${pk.length} B (hash: ${require('crypto').createHash('sha256').update(pk).digest('hex').slice(0, 16)}…)`);

            console.time('  keygenExpand');
            const { wire, apduCount, timingMs } = await keygenExpand(transport);
            console.timeEnd('  keygenExpand');
            console.log(`  wire: ${wire.length} B, ${apduCount} APDUs`);
            console.log(`  timing: compute_l0=${timingMs.compute_l0}ms ` +
                `right=${timingMs.right_stream}ms left=${timingMs.left_stream}ms`);

            // Save the wire so subsequent sign tests can use FEED_SWAP/FEED_TREE_STREAM
            const fs = require('fs');
            const outPath = process.argv[2] || 'falcon512_wire.bin';
            fs.writeFileSync(outPath, wire);
            console.log(`  saved wire to ${outPath}`);
            console.log(`  next: feed this wire into FALCON_SIGN and verify_raw against pk.`);
        } finally {
            await transport.close();
        }
    })().catch(e => { console.error(e); process.exit(1); });
}
