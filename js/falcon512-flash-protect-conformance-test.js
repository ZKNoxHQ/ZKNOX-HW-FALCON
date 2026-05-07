/*
 * falcon512-flash-protect-conformance-test.js
 *
 * Validates the SCA-protected Falcon-512 flash sign (INS 0x66, Algorithms
 * 5/6/7 of Lin et al. PKC 2025).
 *
 * Mirror of the unprotected conformance test:
 *   1. KEYGEN (INS 0x60) once
 *   2. KEYGEN_EXPAND (INS 0x62) once
 *   3. Three sign cases via INS 0x66, with GET_SIG (INS 0x64) — sig
 *      retrieval is shared with the unprotected variant.
 *
 * Sigs from sampler_protect are NOT byte-identical to those from Zf(sampler)
 * for the same seed/message — protected sampler consumes more PRNG tape.
 * Both are valid for the same key/message under verify_raw.
 *
 * Predicted sign duration on Nano S+: ~6 sec (vs ~1 sec unprotected, ×6).
 */

const TransportHID = require("@ledgerhq/hw-transport-node-hid").default;
const crypto = require("crypto");

const { verifyRaw } = require("./falcon-verify-512.js");
const F = require("./falcon512-flash-ledger.js");

const REF_PK_SHA256_512 =
    "f3c31b60497fbac856b8c062ef314db2106755356dbd9777d4bff8b03ea9914e";

const sha256hex = b => crypto.createHash("sha256").update(b).digest("hex");

const CLA = 0xE0;
const INS_SIGN_PROTECT = 0x66;
const SIGN_P1 = {
    INIT:               0x00,
    FEED_MSG:           0x06,
    FEED_NONCE_HOST:    0x08,
    GEN_NONCE_DEVICE:   0x09,
    SIGN_ALL:           0x10,
    GET_NONCE:          0x91,
};

async function send(t, ins, p1, p2, data = Buffer.alloc(0)) {
    return t.send(CLA, ins, p1, p2, data);
}

async function expectSw9000(promise, label) {
    const r = await promise;
    const sw = (r[r.length - 2] << 8) | r[r.length - 1];
    if (sw !== 0x9000) {
        throw new Error(`${label}: SW=${sw.toString(16)} (expected 9000)`);
    }
    return r;
}

async function flashSignProtectInit(t)         { return send(t, INS_SIGN_PROTECT, SIGN_P1.INIT,            0x00); }
async function flashFeedMsgProtect(t, msg)     { return send(t, INS_SIGN_PROTECT, SIGN_P1.FEED_MSG,        0x00, msg); }
async function flashFeedNonceProtect(t, nonce) { return send(t, INS_SIGN_PROTECT, SIGN_P1.FEED_NONCE_HOST, 0x00, nonce); }
async function flashGenNonceProtect(t)         { return send(t, INS_SIGN_PROTECT, SIGN_P1.GEN_NONCE_DEVICE,0x00); }
async function flashSignAllProtect(t)          { return send(t, INS_SIGN_PROTECT, SIGN_P1.SIGN_ALL,        0x00); }
async function flashGetNonceProtect(t)         {
    const r = await send(t, INS_SIGN_PROTECT, SIGN_P1.GET_NONCE, 0x00);
    return r.subarray(0, r.length - 2);
}

async function runOne(transport, label, nonceProvider, msg) {
    console.log(`  → [${label}]`);

    await expectSw9000(flashSignProtectInit(transport), `INIT [${label}]`);

    if (nonceProvider === "device") {
        await expectSw9000(flashGenNonceProtect(transport), `GEN_NONCE [${label}]`);
    } else {
        await expectSw9000(flashFeedNonceProtect(transport, nonceProvider), `FEED_NONCE [${label}]`);
    }

    await expectSw9000(flashFeedMsgProtect(transport, msg), `FEED_MSG [${label}]`);

    const t0 = Date.now();
    await expectSw9000(flashSignAllProtect(transport), `SIGN_ALL [${label}]`);
    console.log(`    sign duration: ${Date.now() - t0} ms`);

    const nonce = await flashGetNonceProtect(transport);
    /* GET_SIG is shared with the unprotected variant — INS 0x64 */
    const sig   = await F.flashGetSig(transport);

    const pk = await F.flashGetPk(transport);
    const v = verifyRaw(pk, msg, nonce, sig);
    if (!v.ok) {
        console.log(`    sqn=${v.sqn}, bound=${v.bound}`);
        throw new Error(`verify_raw FAILED [${label}]`);
    }
    console.log(`    verify_raw OK (sqn=${v.sqn}/${v.bound})`);
}

async function main() {
    const transport = await TransportHID.create();
    transport.setExchangeTimeout(60000);   // protected sign predicted ~6s

    try {
        console.log("[1/3] FALCON512_FLASH_KEYGEN (INS 0x60)");
        await expectSw9000(F.flashKeygen(transport), "KEYGEN");

        const pk = await F.flashGetPk(transport);
        const pkSha = sha256hex(pk);
        console.log(`     pk SHA-256: ${pkSha}`);
        if (pkSha !== REF_PK_SHA256_512) {
            console.log(`     EXPECTED:   ${REF_PK_SHA256_512}`);
            throw new Error("pk SHA mismatch — verify mnemonic is yellow×12");
        }
        console.log("     ✓ pk matches reference");

        console.log("[2/3] FALCON512_FLASH_KEYGEN_EXPAND (INS 0x62)");
        const tExp = Date.now();
        await expectSw9000(F.flashKeygenExpand(transport), "EXPAND");
        console.log(`     expand duration: ${Date.now() - tExp} ms`);

        console.log("[3/3] Three sign cases via INS 0x66 (SCA-protected sampler)");

        const msg = Buffer.from(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "hex");

        await runOne(transport, "deterministic zero nonce",
                     Buffer.alloc(40), msg);

        await runOne(transport, "device TRNG nonce", "device", msg);

        const incNonce = Buffer.alloc(40);
        for (let i = 0; i < 40; i++) incNonce[i] = i + 1;
        await runOne(transport, "deterministic incremental nonce",
                     incNonce, msg);

        console.log("");
        console.log("ALL 3/3 PASSED — Falcon-512 flash SCA-protected sign validated.");
    } finally {
        await transport.close();
    }
}

main().catch(e => {
    console.error("FAIL:", e.message || e);
    process.exit(1);
});
