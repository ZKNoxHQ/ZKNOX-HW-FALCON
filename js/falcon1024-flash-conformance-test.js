/*
 * falcon1024-flash-conformance-test.js
 *
 * End-to-end test for the Falcon-1024 flash variant. Mirrors the structure
 * of falcon512-flash-conformance-test.js with N=1024 and the corresponding
 * reference pk SHA-256.
 *
 * Three sign cases:
 *   1. deterministic zero nonce  (nonce = 40 zero bytes)
 *   2. device TRNG nonce         (GEN_NONCE_DEVICE)
 *   3. deterministic incremental (nonce = 0x01 0x02 ... 0x28)
 *
 * Each case: KEYGEN once → EXPAND once → 3× (INIT/FEED_NONCE/FEED_MSG/SIGN_ALL/GET_NONCE/GET_SIG/verify_raw).
 *
 * NOTE: Falcon-1024 KEYGEN_EXPAND on Nano S+ takes ~30-60 sec (vs ~10 sec
 * for 512). Falcon-1024 SIGN_ALL takes ~2.5 sec. Both well within transport
 * default timeouts only if you bump them — the script does this below.
 */

const TransportHID = require("@ledgerhq/hw-transport-node-hid").default;
const crypto = require("crypto");

const F = require("./falcon1024-flash-ledger.js");
const { verifyRaw } = require("./falcon-verify-1024.js");

/* Reference pk SHA-256 for mnemonic "yellow yellow ... (×12)" */
const REF_PK_SHA256_1024 =
    "abda0932325ead2b390ba6542d6ff45b02e03b2ffdafd338f39667dc152a40d3";

const sha256hex = b => crypto.createHash("sha256").update(b).digest("hex");

async function expectSw9000(promise, label) {
    const r = await promise;
    const sw = (r[r.length - 2] << 8) | r[r.length - 1];
    if (sw !== 0x9000) {
        throw new Error(`${label}: SW=${sw.toString(16)} (expected 9000)`);
    }
    return r;
}

async function runOne(transport, label, nonceProvider, msg) {
    console.log(`  → [${label}]`);

    await expectSw9000(F.flashSignInit(transport), `INIT [${label}]`);

    if (nonceProvider === "device") {
        await expectSw9000(F.flashGenNonceDevice(transport), `GEN_NONCE [${label}]`);
    } else {
        await expectSw9000(F.flashFeedNonceHost(transport, nonceProvider),
                           `FEED_NONCE [${label}]`);
    }

    await expectSw9000(F.flashFeedMsg(transport, msg), `FEED_MSG [${label}]`);

    const t0 = Date.now();
    await expectSw9000(F.flashSignAll(transport), `SIGN_ALL [${label}]`);
    console.log(`    sign duration: ${Date.now() - t0} ms`);

    const nonce = await F.flashGetNonce(transport);
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
    /* Bump exchange timeout: Falcon-1024 expand ≥30s, sign ~2.5s. */
    transport.setExchangeTimeout(120000);

    try {
        console.log("[1/3] FALCON1024_FLASH_KEYGEN");
        await expectSw9000(F.flashKeygen(transport), "KEYGEN");

        const pk = await F.flashGetPk(transport);
        const pkSha = sha256hex(pk);
        console.log(`     pk SHA-256: ${pkSha}`);
        if (pkSha !== REF_PK_SHA256_1024) {
            console.log(`     EXPECTED:   ${REF_PK_SHA256_1024}`);
            throw new Error("pk SHA-256 mismatch — wrong mnemonic on the device?");
        }
        console.log("     ✓ pk matches reference");

        console.log("[2/3] FALCON1024_FLASH_KEYGEN_EXPAND (~30-60 sec)");
        const tExp = Date.now();
        await expectSw9000(F.flashKeygenExpand(transport), "EXPAND");
        console.log(`     expand duration: ${Date.now() - tExp} ms`);

        console.log("[3/3] Three sign cases");

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
        console.log("ALL 3/3 PASSED.");
    } finally {
        await transport.close();
    }
}

main().catch(e => {
    console.error("FAIL:", e.message || e);
    process.exit(1);
});
