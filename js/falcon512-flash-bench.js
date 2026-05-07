/*
 * falcon512-flash-bench.js
 *
 * Benchmarks all four perf-sensitive operations of the Falcon-512 flash
 * variants in a single run:
 *   - INS 0x60: KEYGEN                       (one-shot, NVRAM write)
 *   - INS 0x62: KEYGEN_EXPAND                (one-shot, NVRAM write)
 *   - INS 0x63: SIGN unprotected sampler     (Zf(sampler) baseline)
 *   - INS 0x66: SIGN SCA-protected sampler   (Lin et al. PKC 2025 Algos 5/6/7)
 *
 * Both signs share the same _falcon_sign_area (mutually exclusive at
 * runtime) and the same GET_SIG (INS 0x64). Each iteration uses a fresh
 * random msg + device TRNG nonce, then verifies the resulting sig host-side.
 *
 * Both variants are exercised on the SAME msg in each iteration (different
 * nonce per variant), so any cross-iteration timing drift biases both
 * equally.
 */

const TransportHID = require("@ledgerhq/hw-transport-node-hid").default;
const crypto = require("crypto");

const { verifyRaw } = require("./falcon-verify-512.js");
const F = require("./falcon512-flash-ledger.js");

const REF_PK_SHA256_512 =
    "f3c31b60497fbac856b8c062ef314db2106755356dbd9777d4bff8b03ea9914e";

const sha256hex = b => crypto.createHash("sha256").update(b).digest("hex");

const N_ITERATIONS = 5;   // adjust if you want more samples

const CLA = 0xE0;
const INS_SIGN_UNPROTECT = 0x63;
const INS_SIGN_PROTECT   = 0x66;

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
        throw new Error(`${label}: SW=${sw.toString(16).padStart(4,"0")} (expected 9000)`);
    }
    return r;
}

/* Single sign session via the given INS. Times only the SIGN_ALL APDU
 * (steps before/after — INIT/FEED_NONCE/FEED_MSG/GET_NONCE/GET_SIG —
 * are fixed-cost overhead and not part of the sampler benchmark).
 */
async function signOne(transport, ins, msg) {
    await expectSw9000(send(transport, ins, SIGN_P1.INIT,             0x00),       "INIT");
    await expectSw9000(send(transport, ins, SIGN_P1.GEN_NONCE_DEVICE, 0x00),       "GEN_NONCE");
    await expectSw9000(send(transport, ins, SIGN_P1.FEED_MSG,         0x00, msg),  "FEED_MSG");

    const t0 = Date.now();
    await expectSw9000(send(transport, ins, SIGN_P1.SIGN_ALL,         0x00),       "SIGN_ALL");
    const dur = Date.now() - t0;

    const nonceR = await send(transport, ins, SIGN_P1.GET_NONCE, 0x00);
    const nonce  = nonceR.subarray(0, nonceR.length - 2);
    const sig    = await F.flashGetSig(transport);   /* INS 0x64 shared */

    return { dur, nonce, sig };
}

function stats(arr) {
    const sum = arr.reduce((a, b) => a + b, 0);
    const mean = sum / arr.length;
    const sorted = [...arr].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    return {
        mean:   Math.round(mean),
        median: median,
        min:    Math.min(...arr),
        max:    Math.max(...arr),
    };
}

function fmt(n)    { return String(n).padStart(5, " "); }
function fmtMs(n)  { return fmt(n) + " ms"; }

async function main() {
    const transport = await TransportHID.create();
    transport.setExchangeTimeout(120000);  /* protected sign predicted ~6 sec */

    try {
        console.log("=== Falcon-512 flash bench (unprotected vs SCA-protected sampler) ===\n");

        /* ------------------------------------------------------- KEYGEN */
        console.log("[1] FALCON512_FLASH_KEYGEN (INS 0x60) ...");
        const tK = Date.now();
        await expectSw9000(F.flashKeygen(transport), "KEYGEN");
        const keygenDur = Date.now() - tK;
        console.log(`    duration: ${fmtMs(keygenDur)}`);

        const pk = await F.flashGetPk(transport);
        const pkSha = sha256hex(pk);
        if (pkSha !== REF_PK_SHA256_512) {
            console.log(`    pk SHA-256: ${pkSha}`);
            console.log(`    expected:   ${REF_PK_SHA256_512}`);
            throw new Error("pk SHA mismatch — verify mnemonic is yellow×12");
        }
        console.log(`    ✓ pk matches reference`);

        /* ------------------------------------------------------- EXPAND */
        console.log("\n[2] FALCON512_FLASH_KEYGEN_EXPAND (INS 0x62) ...");
        const tE = Date.now();
        await expectSw9000(F.flashKeygenExpand(transport), "EXPAND");
        const expandDur = Date.now() - tE;
        console.log(`    duration: ${fmtMs(expandDur)}`);

        /* --------------------------------------------- SIGN bench loop */
        console.log(`\n[3] SIGN bench — ${N_ITERATIONS} iterations × 2 variants`);
        console.log("    (msg per iteration: random; nonce per sign: device TRNG)\n");

        const unprotectedTimes = [];
        const protectedTimes   = [];
        let validCount = 0;
        const totalSigns = 2 * N_ITERATIONS;

        for (let i = 0; i < N_ITERATIONS; i++) {
            const msg = crypto.randomBytes(32);
            console.log(`  --- iteration ${i + 1}/${N_ITERATIONS} ---`);

            /* Unprotected (INS 0x63) */
            const u  = await signOne(transport, INS_SIGN_UNPROTECT, msg);
            const vu = verifyRaw(pk, msg, u.nonce, u.sig);
            unprotectedTimes.push(u.dur);
            if (vu.ok) validCount++;
            console.log(`    unprotected (0x63): ${fmtMs(u.dur)}  verify=${vu.ok ? "OK" : "FAIL"}`);

            /* Protected (INS 0x66) */
            const p  = await signOne(transport, INS_SIGN_PROTECT, msg);
            const vp = verifyRaw(pk, msg, p.nonce, p.sig);
            protectedTimes.push(p.dur);
            if (vp.ok) validCount++;
            console.log(`    protected   (0x66): ${fmtMs(p.dur)}  verify=${vp.ok ? "OK" : "FAIL"}`);
        }

        /* ----------------------------------------------------- Summary */
        const u = stats(unprotectedTimes);
        const p = stats(protectedTimes);
        const slowdown = (p.mean / u.mean).toFixed(2);

        console.log("\n=== TIMING SUMMARY ===");
        console.log(`  KEYGEN           (0x60): ${fmtMs(keygenDur)}`);
        console.log(`  KEYGEN_EXPAND    (0x62): ${fmtMs(expandDur)}`);
        console.log(`  SIGN unprotected (0x63): mean=${fmtMs(u.mean)}  median=${fmtMs(u.median)}  min=${fmtMs(u.min)}  max=${fmtMs(u.max)}`);
        console.log(`  SIGN protected   (0x66): mean=${fmtMs(p.mean)}  median=${fmtMs(p.median)}  min=${fmtMs(p.min)}  max=${fmtMs(p.max)}`);
        console.log(`  SCA-protect slowdown (protected_mean / unprotected_mean): ${slowdown}×`);
        console.log("");
        console.log(`Verifications: ${validCount} / ${totalSigns}`);

        if (validCount !== totalSigns) {
            throw new Error(`Some verifications failed (${validCount}/${totalSigns})`);
        }
        console.log("ALL SIGS VALID.");
    } finally {
        await transport.close();
    }
}

main().catch(e => {
    console.error("\nFAIL:", e.message || e);
    process.exit(1);
});
