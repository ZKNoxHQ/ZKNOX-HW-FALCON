/*
 * falcon-verify-512.js — Falcon-512 verify_raw, pure JS (zero deps)
 *
 * Uses Node's built-in `crypto.createHash('shake256', { outputLength })`
 * for SHAKE256, available since Node 12.
 *
 * Inputs (all little-endian like the device):
 *   pk    : Buffer(1024)  — h as uint16 LE × 512
 *   msg   : Buffer(any)   — message digest (ZKNOX uses 32-byte SHA-256/keccak)
 *   nonce : Buffer(40)    — salt
 *   sig   : Buffer(1024)  — signature s2 as int16 LE × 512
 *
 * Returns: { ok: bool, sqn: number, bound: 34034726 }
 *
 * Spec: Falcon round-3 §3.9.3. Implements is_short:
 *   1. hm = hash_to_point_vartime(SHAKE256(nonce || msg))
 *   2. s1 = hm - s2 * h   mod (X^n + 1, q)
 *   3. ||s1||² + ||s2||² ≤ ⌊β² · n⌋ = 34034726 for n=512
 */

const crypto = require("crypto");

const Q     = 12289;
const N     = 512;
const BOUND = 34034726;

/* Pull a generous SHAKE256 stream upfront. hash_to_point_vartime needs ~1280
 * bytes typical for n=512 (rejection rate ~6%, but each accepted value still
 * needs 2 bytes); 8 KB gives us a 6× safety margin. */
const SHAKE_BUF_LEN = 8192;

function shakeBytes(nonce, msg) {
    const h = crypto.createHash("shake256", { outputLength: SHAKE_BUF_LEN });
    h.update(nonce);
    h.update(msg);
    return h.digest();
}

function hashToPointVartime(stream, n) {
    const out = new Uint16Array(n);
    let i = 0;
    let p = 0;
    while (i < n) {
        if (p + 2 > stream.length) {
            throw new Error(`SHAKE buffer exhausted at i=${i}; increase SHAKE_BUF_LEN`);
        }
        const w = (stream[p] << 8) | stream[p + 1];   /* big-endian per Falcon spec */
        p += 2;
        if (w < 61445) {                                /* 5*Q */
            let v = w;
            while (v >= Q) v -= Q;
            out[i++] = v;
        }
    }
    return out;
}

function reduceCentered(v) {
    let r = ((v % Q) + Q) % Q;
    if (r > (Q >> 1)) r -= Q;
    return r;
}

/* s1 = hm - s2 * h   mod (X^n + 1, q).
 * Naive O(n²) — 262 144 mults, ~50 ms in Node. NTT not worth the maintenance. */
function computeS1(hm, s2, h) {
    const s1 = new Float64Array(N);
    for (let k = 0; k < N; k++) s1[k] = hm[k];

    for (let i = 0; i < N; i++) {
        const si = s2[i];
        if (si === 0) continue;
        for (let j = 0; j < N; j++) {
            const k = i + j;
            const prod = si * h[j];
            if (k < N) s1[k]     -= prod;
            else       s1[k - N] += prod;
        }
    }
    const out = new Int32Array(N);
    for (let k = 0; k < N; k++) out[k] = reduceCentered(s1[k]);
    return out;
}

function verifyRaw(pkBuf, msg, nonce, sigBuf) {
    if (pkBuf.length  !== 2 * N) throw new Error(`pk length ${pkBuf.length} !== ${2*N}`);
    if (sigBuf.length !== 2 * N) throw new Error(`sig length ${sigBuf.length} !== ${2*N}`);
    if (nonce.length  !== 40)    throw new Error(`nonce length ${nonce.length} !== 40`);

    const h = new Uint16Array(N);
    for (let i = 0; i < N; i++) {
        h[i] = pkBuf[2*i] | (pkBuf[2*i+1] << 8);
    }

    const s2 = new Int16Array(N);
    for (let i = 0; i < N; i++) {
        const lo = sigBuf[2*i];
        const hi = sigBuf[2*i+1];
        let v = lo | (hi << 8);
        if (v & 0x8000) v -= 0x10000;
        s2[i] = v;
    }

    const stream = shakeBytes(nonce, msg);
    const hm = hashToPointVartime(stream, N);
    const s1 = computeS1(hm, s2, h);

    let sqn = 0;
    for (let i = 0; i < N; i++) {
        sqn += s1[i] * s1[i];
        sqn += s2[i] * s2[i];
    }
    return { ok: sqn <= BOUND, sqn, bound: BOUND };
}

module.exports = { verifyRaw, Q, N, BOUND };
