/* falcon1024-verify.js — Falcon-1024 verify_raw in pure Node JS.
 *
 * Implements the exact same check as Zf(verify_raw) in zknox/falcon/vrfy.c:
 *
 *   Given:
 *     c0  — message hashed to point: 1024 uint16 in [0, q)
 *     s2  — second sig component: 1024 int16, |s2[i]| ≤ ~q/2 typically
 *     h   — public key polynomial: 1024 uint16 in [0, q)
 *
 *   Compute:
 *     s1 = c0 - s2 * h   (mod q, mod X^1024 + 1)
 *
 *   Accept iff:
 *     ||s1||² + ||s2||² ≤ BOUND_FALCON1024 = 34034726
 *
 * Polynomial mult mod (X^1024 + 1) with q=12289 is done schoolbook
 * (~1M ops, ~50–100ms in V8). NTT would be faster but more code.
 *
 * EXPORTS
 *   verifyRaw(hm, sig, h) → bool
 *     hm:  Buffer of 2048 B (1024 LE uint16) — c0
 *     sig: Buffer of 2048 B (1024 LE int16) — s2 raw
 *     h:   Buffer of 2048 B (1024 LE uint16) — public key
 */
'use strict';

const Q = 12289;
const N = 1024;
// Falcon's is_short() bound for n=1024 (logn=10):
//   ||(s1, s2)||² < ((7085 * 12289) >> (10 - logn))   from common.c:Zf(is_short)
//   For logn=10: 7085 * 12289 = 87,067,565
const BOUND_FALCON1024 = 87067565n;

function bufToU16LE(buf) {
    const a = new Uint16Array(N);
    for (let i = 0; i < N; i++) a[i] = buf.readUInt16LE(2 * i);
    return a;
}
function bufToS16LE(buf) {
    const a = new Int16Array(N);
    for (let i = 0; i < N; i++) a[i] = buf.readInt16LE(2 * i);
    return a;
}

/** Polynomial mult mod (X^N + 1) over Z_q, schoolbook.
 *
 * Each individual term a[i]*b[j] fits in int32 (max ~12288² ≈ 151M).
 * But summing 1024 terms can reach ~150 billion, overflowing int32.
 * To avoid overflow we accumulate in a number-typed Float64 array
 * (safe up to 2^53 = ~9e15) and reduce mod q at the end.
 */
function polyMulModXNplus1(a, b) {
    const out = new Float64Array(N);
    for (let i = 0; i < N; i++) {
        const ai = a[i];
        if (ai === 0) continue;
        for (let j = 0; j < N; j++) {
            const k = i + j;
            const term = ai * b[j];
            if (k < N) {
                out[k] += term;
            } else {
                // X^N = -1, so coefficient at k wraps to k-N with negation
                out[k - N] -= term;
            }
        }
    }
    // Reduce mod q
    const r = new Int32Array(N);
    for (let i = 0; i < N; i++) {
        // out[i] is integer-valued double in (-1.6e11, 1.6e11), well below 2^53
        let v = ((out[i] % Q) + Q) % Q;
        r[i] = v;
    }
    return r;
}

/**
 * Verify a Falcon-1024 raw signature.
 *
 * @param {Buffer} hmBuf   2048 B, 1024 LE uint16 — c0 = hash_to_point output
 * @param {Buffer} sigBuf  2048 B, 1024 LE int16  — s2 raw (device GET_SIG output)
 * @param {Buffer} hBuf    2048 B, 1024 LE uint16 — pk polynomial
 * @returns {boolean} true iff sig valid
 */
function verifyRaw(hmBuf, sigBuf, hBuf) {
    if (hmBuf.length !== 2 * N) throw new Error(`hm size: ${hmBuf.length} vs ${2*N}`);
    if (sigBuf.length !== 2 * N) throw new Error(`sig size: ${sigBuf.length} vs ${2*N}`);
    if (hBuf.length !== 2 * N) throw new Error(`h size: ${hBuf.length} vs ${2*N}`);

    const c0 = bufToU16LE(hmBuf);
    const s2 = bufToS16LE(sigBuf);
    const h  = bufToU16LE(hBuf);

    // s2 mod q (s2 is signed but we lift to [0, q) for poly mult)
    const s2_mod = new Int32Array(N);
    for (let i = 0; i < N; i++) {
        let v = s2[i] % Q;
        if (v < 0) v += Q;
        s2_mod[i] = v;
    }

    // s1 = c0 - s2 * h  (mod q, mod X^N + 1)
    const s2h = polyMulModXNplus1(s2_mod, h);
    const s1 = new Int32Array(N);
    for (let i = 0; i < N; i++) {
        let v = (c0[i] - s2h[i]) % Q;
        if (v < 0) v += Q;
        s1[i] = v;
    }

    // For norm: lift s1 from [0, q) to [-q/2, q/2]
    // Falcon: if x > q/2, treat as x - q (signed representation)
    const HALF_Q = (Q - 1) >> 1; // 6144
    let normSq = 0n;
    for (let i = 0; i < N; i++) {
        let v = s1[i];
        if (v > HALF_Q) v -= Q;
        normSq += BigInt(v * v);
    }
    for (let i = 0; i < N; i++) {
        const v = s2[i];
        normSq += BigInt(v * v);
    }

    return normSq <= BOUND_FALCON1024;
}

/**
 * Hash-to-point (host-side) — produces the c0 polynomial that the device
 * will consume via FEED_HM. Falcon spec hash_to_point_vartime:
 *   - SHAKE256 absorb (nonce || msg)
 *   - extract uint16 LE values; reject those ≥ k*q (k = 5 for n=1024)
 *   - keep first N accepted values, modulo q
 *
 * @param {Buffer} nonce  40 random bytes
 * @param {Buffer} msg    arbitrary
 * @returns {Buffer}      hm buffer (2048 B, 1024 LE uint16)
 */
function hashToPoint(nonce, msg) {
    const crypto = require('crypto');
    if (nonce.length !== 40) throw new Error('nonce must be 40 B');

    // Falcon's hash_to_point_vartime uses k = (1u << 16) / q ≈ 5.
    // Reject samples ≥ 5*q = 61445.  Acceptance rate ≈ 0.937, so on average
    // we need 1024/0.937 ≈ 1093 samples = 2186 SHAKE bytes for n=1024.
    // 8192 bytes give >7σ headroom; if it ever proves insufficient we'd
    // need to switch to a streaming SHAKE API (Node's crypto SHAKE is
    // fixed-length, so re-squeezing is not straightforward).
    const REJECT_THRESHOLD = 5 * Q;
    const SHAKE_BYTES = 8192;

    const h = crypto.createHash('shake256', { outputLength: SHAKE_BYTES });
    h.update(nonce);
    h.update(msg);
    const block = h.digest();

    const out = Buffer.alloc(2 * N);
    let collected = 0;
    for (let i = 0; i < block.length - 1 && collected < N; i += 2) {
        // Falcon spec: BIG-endian extract from the SHAKE stream.
        const w = (block[i] << 8) | block[i + 1];
        if (w < REJECT_THRESHOLD) {
            // Reduce mod q via repeated subtraction (matches the C ref).
            let r = w;
            while (r >= Q) r -= Q;
            out.writeUInt16LE(r, 2 * collected);
            collected++;
        }
    }
    if (collected < N) {
        throw new Error(
            `hash_to_point: SHAKE budget (${SHAKE_BYTES} B) yielded only ${collected}/${N} ` +
            `accepted samples — extremely unlikely; please report.`
        );
    }
    return out;
}

module.exports = { verifyRaw, hashToPoint, Q, N, BOUND_FALCON1024 };

// Self-test if run directly
if (require.main === module) {
    console.log('Falcon-1024 verify_raw module loaded.');
    console.log('  Q =', Q);
    console.log('  N =', N);
    console.log('  bound (||s1||² + ||s2||² ≤) =', BOUND_FALCON1024.toString());
    console.log();
    console.log('Quick smoke test of polyMulModXNplus1:');
    const a = new Int32Array(N);
    const b = new Int32Array(N);
    a[0] = 1;
    b[0] = 1;
    const ab = polyMulModXNplus1(a, b);
    console.log('  (1) * (1) = ' + ab[0] + ' (expect 1)' +
                (ab[0] === 1 ? ' ✓' : ' ✗'));
    a[0] = 0; a[1] = 1; // X
    b[0] = 0; b[N-1] = 1; // X^(N-1)
    const ab2 = polyMulModXNplus1(a, b);
    // X * X^(N-1) = X^N = -1 (mod X^N + 1) → coefficient 0 = q-1
    console.log('  X * X^(N-1) = -1 mod (X^N+1):');
    console.log('    coeff[0] = ' + ab2[0] + ' (expect ' + (Q-1) + ')' +
                (ab2[0] === Q-1 ? ' ✓' : ' ✗'));
}
