/*
 * falcon512-flash-conformance-test.js — phase 2b end-to-end test
 *
 * Sequence:
 *   1. flashKeygen + flashKeygenExpand (re-derive + re-fill NVRAM)
 *   2. flashGetPk → check SHA-256 == reference (sanity)
 *   3. Sign deterministic (nonce all-zero, msg = SHA256("ZKNOX phase 2b"))
 *      via flashSignInit / flashFeedMsg / flashFeedNonceHost / flashSignAll
 *   4. flashGetSig → 1024 bytes int16 LE
 *   5. verifyRaw(pk, msg, nonce, sig) → must return ok=true
 *   6. Repeat with device-generated nonce (flashGenNonceDevice)
 *
 * PASS criteria: both signs verify, sqn under bound.
 *
 * Why this proves end-to-end correctness:
 *   - A single wrong byte in the LDL tree → sampler diverges → s1, s2 don't
 *     satisfy s2*h + s1 = hm → norm explodes → verify fails.
 *   - PASS ⇒ NVRAM tree is mathematically correct AND sign reads it correctly.
 *
 * Run:
 *   $ node falcon512-flash-conformance-test.js
 */

const Transport = require("@ledgerhq/hw-transport-node-hid").default;
const crypto = require("crypto");
const {
    flashKeygen,
    flashKeygenExpand,
    flashGetPk,
    flashSignInit,
    flashFeedMsg,
    flashFeedNonceHost,
    flashGenNonceDevice,
    flashSignAll,
    flashGetNonce,
    flashGetSig,
} = require("./falcon512-flash-ledger");
const { verifyRaw } = require("./falcon-verify-512");

/* Reference for mnemonic = "yellow yellow yellow ... × 12" */
const REF_PK_SHA256_512 =
    "f3c31b60497fbac856b8c062ef314db2106755356dbd9777d4bff8b03ea9914e";

function sha256hex(buf) {
    return crypto.createHash("sha256").update(buf).digest("hex");
}

function pad(label, n = 28) {
    return label + " ".repeat(Math.max(1, n - label.length));
}

async function runOnce(transport, label, getNonce) {
    console.log(`\n--- ${label} ---`);

    /* 3a. INIT */
    await flashSignInit(transport);
    console.log(pad("  flashSignInit"), "OK");

    /* 3b. FEED_MSG: SHA-256("ZKNOX phase 2b - " + label) */
    const msg = crypto.createHash("sha256")
                      .update("ZKNOX phase 2b - " + label)
                      .digest();
    await flashFeedMsg(transport, msg);
    console.log(pad("  flashFeedMsg"), `${msg.toString("hex").slice(0, 16)}...`);

    /* 3c. nonce: either host-supplied (deterministic) or device TRNG */
    const nonce = await getNonce(transport);
    console.log(pad("  nonce"), `${nonce.toString("hex").slice(0, 16)}...`);

    /* 3d. SIGN_ALL — synchronous on-device, ~1 sec */
    const t0 = Date.now();
    await flashSignAll(transport);
    const dt = Date.now() - t0;
    console.log(pad("  flashSignAll"), `OK (${dt} ms)`);

    /* 4. Pull sig */
    const sig = await flashGetSig(transport);
    console.log(pad("  flashGetSig"), `${sig.length} bytes, sha256=${sha256hex(sig).slice(0, 16)}...`);

    /* 5. Pull pk and run verify_raw */
    const pk = await flashGetPk(transport);
    const pkSha = sha256hex(pk);
    if (pkSha !== REF_PK_SHA256_512) {
        throw new Error(`pk SHA mismatch: got ${pkSha}, expected ${REF_PK_SHA256_512}`);
    }
    console.log(pad("  pk SHA-256"), `${pkSha.slice(0, 16)}... ✓`);

    const result = verifyRaw(pk, msg, nonce, sig);
    console.log(pad("  verifyRaw"), `ok=${result.ok}, sqn=${result.sqn}, bound=${result.bound}`);

    if (!result.ok) {
        throw new Error(
            `verify_raw FAILED: sqn=${result.sqn} > bound=${result.bound}`
        );
    }
    return result;
}

async function main() {
    const transport = await Transport.create();
    transport.setExchangeTimeout(60000);   /* 60 sec, KEYGEN_EXPAND is slow */

    try {
        console.log("=== Falcon-512 flash variant — phase 2b conformance ===\n");

        /* 1. Keygen + Expand (re-deriving from mnemonic; idempotent) */
        await flashKeygen(transport);
        console.log(pad("flashKeygen"), "OK");
        const t0 = Date.now();
        await flashKeygenExpand(transport);
        console.log(pad("flashKeygenExpand"), `OK (${Date.now() - t0} ms)`);

        /* Test 1: deterministic nonce (all-zero) — easy to reproduce, regressions
         * stand out clearly. */
        await runOnce(transport, "deterministic nonce (zeros)", async () => {
            const nonce = Buffer.alloc(40, 0);
            await flashFeedNonceHost(transport, nonce);
            return nonce;
        });

        /* Test 2: device-generated nonce — tests TRNG path + GET_NONCE */
        await runOnce(transport, "device-generated nonce", async () => {
            await flashGenNonceDevice(transport);
            return await flashGetNonce(transport);
        });

        /* Test 3: deterministic with different message — second call after a
         * sign already happened (state was reset by INIT, so should be fine) */
        await runOnce(transport, "second deterministic", async () => {
            const nonce = Buffer.alloc(40);
            for (let i = 0; i < 40; i++) nonce[i] = i;
            await flashFeedNonceHost(transport, nonce);
            return nonce;
        });

        console.log("\n=== ALL TESTS PASSED ✓ ===");
        console.log("Phase 2b validated: NVRAM LDL tree is mathematically correct,");
        console.log("flash sign reads it correctly, signatures verify host-side.");

    } catch (err) {
        console.error("\n=== FAILURE ===");
        console.error(err);
        process.exit(1);
    } finally {
        await transport.close();
    }
}

main();
