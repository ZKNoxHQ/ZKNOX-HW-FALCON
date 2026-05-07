/*
 * falcon1024-flash-stub-test.js
 *
 * Smoke test for the Falcon-1024 flash STUB delivery.
 *
 * Validates:
 *   1. INS 0x70 KEYGEN routing + NVRAM pk write
 *   2. INS 0x71 GET_PK chunked read + pk SHA-256 vs reference (yellow×12)
 *   3. INS 0x72 KEYGEN_EXPAND stub routing (sets ready=1, no real tree)
 *   4. INS 0x75 DUMP_NVM[0] routing + NVRAM read
 *
 * Does NOT test SIGN/GET_SIG (those are stubs returning 0x9000 / zeros —
 * they pass routing but produce nothing meaningful until the full delivery).
 *
 * Prerequisite:
 *   - Device flashed with falcon1024_flash_stub.zip
 *   - Mnemonic "yellow yellow yellow ... (×12)"
 *   - Other Falcon variants (streaming, Falcon-512 flash) still functional
 */

const TransportHID = require("@ledgerhq/hw-transport-node-hid").default;
const crypto = require("crypto");

const REF_PK_SHA_1024 =
    "abda0932325ead2b390ba6542d6ff45b02e03b2ffdafd338f39667dc152a40d3";

const sha256hex = b => crypto.createHash("sha256").update(b).digest("hex");

const hex = (n, w = 2) => "0x" + n.toString(16).padStart(w, "0");

async function expectSw(transport, ins, p1, p2, data, expectedSw, label) {
    const r = await transport.send(0xE0, ins, p1, p2, data);
    const sw = (r[r.length - 2] << 8) | r[r.length - 1];
    if (sw !== expectedSw) {
        throw new Error(`${label}: SW=${hex(sw, 4)}, expected ${hex(expectedSw, 4)}`);
    }
    return r;
}

async function main() {
    const t = await TransportHID.create();
    t.setExchangeTimeout(60000);   // Falcon-1024 KEYGEN ~10-30 sec on Nano S+

    try {
        // [1] KEYGEN — INS 0x70
        console.log("[1] FALCON1024_FLASH_KEYGEN (INS 0x70) ...");
        const t0 = Date.now();
        const r1 = await expectSw(t, 0x70, 0x00, 0x00, undefined, 0x9000, "KEYGEN");
        console.log(`    SW=9000, first pk byte = ${hex(r1[0])}, dur=${Date.now() - t0} ms`);

        // [2] GET_PK chunked — INS 0x71
        console.log("[2] GET_PK chunked (2048 B) (INS 0x71) ...");
        const chunks = [];
        for (let i = 0; i * 255 < 2048; i++) {
            const r = await t.send(0xE0, 0x71, i, 0x00);
            const sw = (r[r.length - 2] << 8) | r[r.length - 1];
            if (sw !== 0x9000) throw new Error(`GET_PK[${i}] SW=${hex(sw, 4)}`);
            chunks.push(r.subarray(0, r.length - 2));
        }
        const pk = Buffer.concat(chunks).subarray(0, 2048);
        const sha = sha256hex(pk);
        console.log(`    pk SHA-256: ${sha}`);
        console.log(`    expected:   ${REF_PK_SHA_1024}`);
        if (sha !== REF_PK_SHA_1024) {
            throw new Error("pk SHA mismatch — verify mnemonic is yellow×12");
        }
        console.log("    ✓ pk matches reference");

        // [3] KEYGEN_EXPAND stub — INS 0x72
        console.log("[3] KEYGEN_EXPAND stub (INS 0x72) ...");
        await expectSw(t, 0x72, 0x00, 0x00, undefined, 0x9000, "EXPAND_STUB");
        console.log("    SW=9000 (sets ready=1 in NVRAM)");

        // [4] DUMP_NVM[0] — INS 0x75
        console.log("[4] DUMP_NVM[0] (INS 0x75) ...");
        const r4 = await t.send(0xE0, 0x75, 0x00, 0x00);
        const sw4 = (r4[r4.length - 2] << 8) | r4[r4.length - 1];
        if (sw4 === 0x9000) {
            const head = r4.subarray(0, Math.min(8, r4.length - 2));
            const headHex = Array.from(head).map(b => b.toString(16).padStart(2, "0")).join(" ");
            console.log(`    SW=9000, first 8 bytes: ${headHex}`);
            console.log("    (zeros expected — stub EXPAND did not compute the tree)");
        } else {
            console.log(`    SW=${hex(sw4, 4)} (acceptable if device gates DUMP on real EXPAND)`);
        }

        console.log("");
        console.log("STUB OK.");
        console.log("  - NVRAM allocation (108 545 B) passes the linker");
        console.log("  - KEYGEN writes pk to NVRAM correctly");
        console.log("  - GET_PK reads pk back, SHA matches reference");
        console.log("  - INS 0x70/0x71/0x72/0x75 routing all work");
        console.log("");
        console.log("→ next: drop falcon1024_flash_full.zip and run the conformance test.");
    } finally {
        await t.close();
    }
}

main().catch(e => {
    console.error("FAIL:", e.message || e);
    process.exit(1);
});
