#!/usr/bin/env node
/* falcon1024-kat-verify.js — Replay NIST round 3 KAT vectors against the
 * pure-JS Falcon-1024 verify_raw.
 *
 * Validates that this codebase's verify path is byte-conformant with the
 * Falcon round 3 reference implementation, by replaying every vector of a
 * KAT (.rsp) file and checking each (pk, msg, sm) signs verifies.
 *
 * NOTE: this only validates VERIFY, not SIGN. Falcon's signer is
 * probabilistic (gaussian sampler) and its byte-output depends on the PRNG
 * seeding, which differs between this firmware and the NIST DRBG. So sigs
 * can't be byte-replayed; only the verify path must be conformant.
 *
 * USAGE
 *   node falcon1024-kat-verify.js <path/to/PQCsignKAT_1024.rsp>
 *
 * INPUT FORMAT
 *   The .rsp file is the output of the NIST KAT generator. It contains
 *   blocks separated by blank lines:
 *
 *     count = 0
 *     seed  = <96 hex chars>
 *     mlen  = <int>
 *     msg   = <hex>
 *     pk    = <hex>
 *     sk    = <hex>
 *     smlen = <int>
 *     sm    = <hex>
 *
 *   For Falcon-1024:
 *     pk encoding:   1 header byte (0x09) + 1792 bytes (1024 * 14 bits)
 *     sm encoding:   nonce(40) || msg(mlen) || sig_header(1) || sig_compressed(...)
 *                    where sig_header = 0x29 (PADDED, logn=10) or 0x39 (CT)
 */
'use strict';
const fs = require('fs');
const { verifyRaw, hashToPoint, Q, N } = require('./falcon1024-verify');

/* ── Falcon round 3 codecs (JS port of zknox/falcon/codec.c) ─────── */

/**
 * modq_decode: decode 1024 14-bit values into uint16 mod q.
 * Matches Zf(modq_decode) in codec.c.
 *
 * @param {Buffer} input  at least 1792 bytes
 * @returns {Uint16Array(N)} polynomial coefficients in [0, q)
 */
function modqDecode(input) {
    const inLen = ((N * 14) + 7) >> 3; // 1792
    if (input.length < inLen) throw new Error(`pk too short: ${input.length} < ${inLen}`);
    const x = new Uint16Array(N);
    let acc = 0, accLen = 0, u = 0, p = 0;
    while (u < N) {
        acc = ((acc << 8) >>> 0) | input[p++];
        accLen += 8;
        if (accLen >= 14) {
            accLen -= 14;
            const w = (acc >>> accLen) & 0x3FFF;
            if (w >= Q) throw new Error(`modq_decode: w=${w} ≥ q=${Q} at index ${u}`);
            x[u++] = w;
        }
    }
    if ((acc & ((1 << accLen) - 1)) !== 0)
        throw new Error('modq_decode: trailing bits non-zero');
    return x;
}

/**
 * Convert a uint16 polynomial array to the 2048-byte LE buffer that
 * verifyRaw expects (1024 × LE uint16).
 */
function polyToBuf(poly) {
    const out = Buffer.alloc(2 * N);
    for (let i = 0; i < N; i++) out.writeUInt16LE(poly[i], 2 * i);
    return out;
}

/**
 * comp_decode: decode Falcon round 3 compressed signature → 1024 int16.
 * Matches Zf(comp_decode) in codec.c.
 *
 * @param {Buffer} input  the bytes after the sig header
 * @returns {{sig: Int16Array(N), bytesConsumed: number}}
 */
function compDecode(input) {
    const x = new Int16Array(N);
    let acc = 0, accLen = 0, v = 0;
    for (let u = 0; u < N; u++) {
        if (v >= input.length) throw new Error(`comp_decode: input too short at u=${u}`);
        acc = ((acc << 8) >>> 0) | input[v++];
        const b = (acc >>> accLen) & 0xFF;
        const s = b & 128;
        let m = b & 127;
        for (;;) {
            if (accLen === 0) {
                if (v >= input.length) throw new Error(`comp_decode: input too short at u=${u} (unary)`);
                acc = ((acc << 8) >>> 0) | input[v++];
                accLen = 8;
            }
            accLen--;
            if (((acc >>> accLen) & 1) !== 0) break;
            m += 128;
            if (m > 2047) throw new Error(`comp_decode: m too large at u=${u}`);
        }
        x[u] = s ? -m : m;
    }
    return { sig: x, bytesConsumed: v };
}

/**
 * Convert Int16Array(N) sig to the 2048-byte LE buffer verifyRaw expects.
 */
function sigToBuf(sig) {
    const out = Buffer.alloc(2 * N);
    for (let i = 0; i < N; i++) out.writeInt16LE(sig[i], 2 * i);
    return out;
}

/* ── KAT (.rsp) parser ───────────────────────────────────────────── */

/**
 * Parse a NIST KAT .rsp file into an array of vector objects.
 * Each vector has: count, seed, mlen, msg, pk, sk, smlen, sm.
 * msg/seed/pk/sk/sm are returned as Buffer; counts/lengths as Number.
 */
function parseKatFile(text) {
    const out = [];
    let cur = null;
    for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) {
            if (cur && cur.count !== undefined) { out.push(cur); cur = null; }
            continue;
        }
        if (line.startsWith('#')) continue;
        const eq = line.indexOf('=');
        if (eq < 0) continue;
        const key = line.slice(0, eq).trim();
        const val = line.slice(eq + 1).trim();
        if (cur === null) cur = {};
        if (key === 'count' || key === 'mlen' || key === 'smlen') {
            cur[key] = parseInt(val, 10);
        } else if (key === 'seed' || key === 'msg' || key === 'pk' ||
                   key === 'sk' || key === 'sm') {
            cur[key] = Buffer.from(val, 'hex');
        }
        // Other keys silently ignored
    }
    if (cur && cur.count !== undefined) out.push(cur);
    return out;
}

/* ── Single-vector verifier ──────────────────────────────────────── */

/**
 * Verify one KAT vector by replay.
 * @param {object} vec  { count, mlen, msg, pk, smlen, sm }
 * @returns {{ok: boolean, reason: string, details: object}}
 */
function verifyKatVector(vec) {
    /* 1. Decode pk. Falcon-1024 round 3 pk format: header(1) + modq(1792). */
    if (vec.pk.length < 1 + 1792) {
        return { ok: false, reason: `pk too short: ${vec.pk.length}` };
    }
    const pkHeader = vec.pk[0];
    /* Header is 0x00+logn → 0x0A for n=1024. Some KAT files use 0x09 historically. */
    if (pkHeader !== 0x0A && pkHeader !== 0x09) {
        return { ok: false, reason: `unknown pk header byte 0x${pkHeader.toString(16)}` };
    }
    let h;
    try {
        h = modqDecode(vec.pk.slice(1, 1 + 1792));
    } catch (e) {
        return { ok: false, reason: `modq_decode failed: ${e.message}` };
    }
    const hBuf = polyToBuf(h);

    /* 2. Parse sm. Format: nonce(40) || msg(mlen) || sig_header(1) || sig_compressed(...) */
    if (vec.sm.length < 40 + vec.mlen + 1) {
        return { ok: false, reason: `sm too short: ${vec.sm.length}` };
    }
    const nonce = vec.sm.slice(0, 40);
    const msgInSm = vec.sm.slice(40, 40 + vec.mlen);
    if (!msgInSm.equals(vec.msg)) {
        return { ok: false, reason: `msg in sm differs from KAT msg` };
    }
    const sigHeader = vec.sm[40 + vec.mlen];
    /* Round 3: 0x20+logn for COMPRESSED(0x2A), 0x30+logn for PADDED(0x3A), 0x40+logn for CT(0x4A) */
    const sigBody = vec.sm.slice(40 + vec.mlen + 1);
    let sig;
    try {
        const result = compDecode(sigBody);
        sig = result.sig;
    } catch (e) {
        return { ok: false, reason: `comp_decode failed: ${e.message} (header=0x${sigHeader.toString(16)})` };
    }
    const sigBuf = sigToBuf(sig);

    /* 3. Compute hm = hash_to_point(nonce || msg) and run verifyRaw. */
    const hm = hashToPoint(nonce, vec.msg);
    let ok;
    try {
        ok = verifyRaw(hm, sigBuf, hBuf);
    } catch (e) {
        return { ok: false, reason: `verifyRaw threw: ${e.message}` };
    }
    return {
        ok,
        reason: ok ? 'VALID' : 'norm bound exceeded',
        details: { nonce: nonce.toString('hex').slice(0, 16) + '…',
                   sigHeader: '0x' + sigHeader.toString(16),
                   pkHeader:  '0x' + pkHeader.toString(16) }
    };
}

/* ── Main ────────────────────────────────────────────────────────── */

function main() {
    const path = process.argv[2];
    if (!path) {
        console.error('Usage: node falcon1024-kat-verify.js <PQCsignKAT_1024.rsp>');
        process.exit(2);
    }
    if (!fs.existsSync(path)) {
        console.error(`File not found: ${path}`);
        process.exit(2);
    }

    console.log(`═══ Falcon-1024 KAT replay (verify only) ═══`);
    console.log(`File: ${path}`);
    const text = fs.readFileSync(path, 'utf8');
    const vectors = parseKatFile(text);
    console.log(`Parsed ${vectors.length} vectors\n`);

    if (vectors.length === 0) {
        console.error('No vectors parsed — wrong file format?');
        process.exit(2);
    }

    /* Sanity: print first vector's metadata */
    const first = vectors[0];
    console.log(`First vector: count=${first.count} mlen=${first.mlen} smlen=${first.smlen}`);
    console.log(`              pk=${first.pk?.length}B sm=${first.sm?.length}B`);
    if (first.pk) console.log(`              pk[0..3]=${first.pk.slice(0,4).toString('hex')}`);
    if (first.sm) console.log(`              sm[0..3]=${first.sm.slice(0,4).toString('hex')}`);
    console.log();

    let pass = 0, fail = 0;
    const failures = [];
    const t0 = Date.now();
    for (const vec of vectors) {
        const r = verifyKatVector(vec);
        if (r.ok) {
            pass++;
        } else {
            fail++;
            failures.push({ count: vec.count, reason: r.reason });
            if (failures.length <= 3) {
                console.log(`  ❌ count=${vec.count}: ${r.reason}`, r.details || '');
            }
        }
        if ((pass + fail) % 10 === 0) {
            process.stdout.write(`\r  progress: ${pass + fail}/${vectors.length}`);
        }
    }
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    process.stdout.write('\r' + ' '.repeat(60) + '\r');
    console.log(`Done in ${elapsed}s.`);
    console.log(`  ✅ pass: ${pass}/${vectors.length}`);
    console.log(`  ❌ fail: ${fail}/${vectors.length}`);
    if (fail > 0 && failures.length > 3) {
        console.log(`  (first 3 failures shown above; ${failures.length - 3} more)`);
    }

    if (fail === 0) {
        console.log('\n═══ ✅ ALL KAT VECTORS PASSED ═══');
        console.log('   This implementation is verify-conformant with Falcon round 3 KAT.');
    }
    process.exit(fail === 0 ? 0 : 1);
}

if (require.main === module) main();
module.exports = { parseKatFile, verifyKatVector, modqDecode, compDecode };
