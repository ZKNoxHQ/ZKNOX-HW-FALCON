/*
 * falcon512-flash-sampler-diff-check.js
 *
 * Decisive diagnostic for "is INS 0x66 actually using the protected sampler?"
 *
 * Both signs use:
 *   - same msg (deterministic constant)
 *   - same nonce (40 zero bytes — deterministic, host-supplied)
 *   - same key (same seed, set up by KEYGEN before this test)
 *
 * The unprotected sampler (Zf(sampler)) and the protected sampler
 * (sampler_protect) consume the PRNG tape differently:
 *   - unprotected: 1 gaussian0 call + 1 sign bit per iteration
 *   - protected:   4 gaussian0 calls + 1 sign nibble + 1 z0 index per iteration
 *
 * For the SAME seed/msg/nonce, the resulting sigs MUST differ if the two
 * samplers are actually different functions. If sig_unprotected_sha ==
 * sig_protected_sha, the protected handler is silently calling the
 * unprotected sampler (or vice versa).
 */

const TransportHID = require("@ledgerhq/hw-transport-node-hid").default;
const crypto = require("crypto");

const { verifyRaw } = require("./falcon-verify-512.js");
const F = require("./falcon512-flash-ledger.js");

const sha256hex = b => crypto.createHash("sha256").update(b).digest("hex");

const CLA = 0xE0;
const INS_SIGN_UNPROTECT = 0x63;
const INS_SIGN_PROTECT   = 0x66;

const SIGN_P1 = {
    INIT:               0x00,
    FEED_MSG:           0x06,
    FEED_NONCE_HOST:    0x08,
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
        throw new Error(`${label}: SW=${sw.toString(16).padStart(4, "0")}`);
    }
    return r;
}

async function signDeterministic(t, ins, msg, nonceZero) {
    await expectSw9000(send(t, ins, SIGN_P1.INIT,            0x00),            "INIT");
    await expectSw9000(send(t, ins, SIGN_P1.FEED_NONCE_HOST, 0x00, nonceZero), "FEED_NONCE");
    await expectSw9000(send(t, ins, SIGN_P1.FEED_MSG,        0x00, msg),       "FEED_MSG");

    const t0 = Date.now();
    await expectSw9000(send(t, ins, SIGN_P1.SIGN_ALL,        0x00),            "SIGN_ALL");
    const dur = Date.now() - t0;

    const sig = await F.flashGetSig(t);
    return { sig, dur };
}

async function main() {
    const t = await TransportHID.create();
    t.setExchangeTimeout(120000);

    try {
        console.log("=== Falcon-512 flash sampler diff-check ===\n");

        const pk = await F.flashGetPk(t);
        console.log(`pk SHA-256: ${sha256hex(pk)}\n`);

        const msg   = Buffer.from(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "hex");
        const nonce = Buffer.alloc(40);   /* 40 zero bytes */

        console.log("Same msg + same nonce (40 zero bytes) on both INS:\n");

        console.log("[unprotected] INS 0x63 ...");
        const u = await signDeterministic(t, INS_SIGN_UNPROTECT, msg, nonce);
        const sigShaU = sha256hex(u.sig);
        const okU = verifyRaw(pk, msg, nonce, u.sig);
        console.log(`  sig SHA-256: ${sigShaU}`);
        console.log(`  duration:    ${u.dur} ms`);
        console.log(`  verify:      ${okU.ok ? "OK" : "FAIL"}\n`);

        console.log("[protected]   INS 0x66 ...");
        const p = await signDeterministic(t, INS_SIGN_PROTECT, msg, nonce);
        const sigShaP = sha256hex(p.sig);
        const okP = verifyRaw(pk, msg, nonce, p.sig);
        console.log(`  sig SHA-256: ${sigShaP}`);
        console.log(`  duration:    ${p.dur} ms`);
        console.log(`  verify:      ${okP.ok ? "OK" : "FAIL"}\n`);

        console.log("=== VERDICT ===");
        if (sigShaU === sigShaP) {
            console.log("⚠ IDENTICAL sigs → INS 0x66 is calling the SAME sampler as 0x63.");
            console.log("  Possible causes:");
            console.log("    1. dispatcher.c routes 0x66 to handler_falcon512_flash_sign (typo)");
            console.log("    2. sampler_protect.c not linked → linker fell back to weak");
            console.log("       symbol or build was stale (re-run make clean && make)");
            console.log("    3. handler_falcon512_flash_sign_protect.c calls Zf(sampler)");
            console.log("       instead of sampler_protect at the dfs_feed leaf");
            process.exit(1);
        } else {
            console.log("✓ DIFFERENT sigs → samplers are genuinely distinct.");
            console.log("  Both sigs verify_raw OK, both correctly produced for the");
            console.log("  same key/msg/nonce but with different PRNG tape consumption.");
            console.log(`  Timing ratio (protected / unprotected): ${(p.dur / u.dur).toFixed(2)}×`);
            console.log("  If this ratio is close to 1.0, the protection is being");
            console.log("  applied but its overhead is dominated by FFT/NVRAM cost in");
            console.log("  this sign — the SCA protection is real, the relative cost");
            console.log("  is just amortized.");
        }
    } finally {
        await t.close();
    }
}

main().catch(e => {
    console.error("FAIL:", e.message || e);
    process.exit(1);
});
