/*
 * dump-streaming-references.js
 *
 * Runs streaming-variant keygen + GET_PK for both Falcon-1024 and
 * Falcon-512 on a connected Ledger Nano S+, computes the pk SHA-256
 * for each, and prints the values in copy-paste-ready form.
 *
 * Pre-requisites:
 *   - App flashed with the streaming variant (your current main branch)
 *   - Device unlocked, app open
 *   - Mnemonic = "yellow yellow yellow yellow yellow yellow yellow
 *                 yellow yellow yellow yellow yellow", no passphrase
 *   - npm install @ledgerhq/hw-transport-node-hid
 *
 * Usage:
 *   node dump-streaming-references.js
 *
 * Note: each keygen takes ~17.8 s for 1024 and ~2.4 s for 512, plus
 * any on-screen confirmation prompts your app might require. Total
 * runtime ~25-40 s.
 *
 * Output: a block of `const REF_PK_SHA256_* = '...';` lines you paste
 * back to me, and I'll integrate them as strict references in both
 * the streaming and flash test files.
 */

const crypto = require('crypto');
const TransportNodeHid = require('@ledgerhq/hw-transport-node-hid').default;

const CLA = 0xE0;

/* Streaming variant INS codes (your current build) */
const STREAMING_1024 = {
  KEYGEN: 0x30,
  GET_PK: 0x31,
  PK_SIZE: 2048,
  LABEL:  'Falcon-1024',
};

const STREAMING_512 = {
  KEYGEN: 0x40,
  GET_PK: 0x41,
  PK_SIZE: 1024,
  LABEL:  'Falcon-512',
};


async function exchange(transport, ins, p1 = 0, p2 = 0, data = Buffer.alloc(0)) {
  const apdu = Buffer.concat([
    Buffer.from([CLA, ins, p1, p2, data.length]),
    data,
  ]);
  const resp = await transport.exchange(apdu);
  const sw = resp.readUInt16BE(resp.length - 2);
  if (sw !== 0x9000) {
    throw new Error(`APDU INS=0x${ins.toString(16)} returned SW=0x${sw.toString(16).padStart(4, '0')}`);
  }
  return resp.slice(0, resp.length - 2);
}


async function getPkChunked(transport, getPkIns, pkSize) {
  const chunks = [];
  let off = 0;
  for (let p1 = 0; off < pkSize; p1++) {
    const c = await exchange(transport, getPkIns, p1, 0);
    chunks.push(c);
    off += c.length;
    if (p1 > 50) throw new Error('GET_PK runaway');
  }
  return Buffer.concat(chunks).slice(0, pkSize);
}


async function dumpVariant(transport, cfg) {
  console.log(`\n--- ${cfg.LABEL} streaming ---`);

  console.log(`  running KEYGEN (INS=0x${cfg.KEYGEN.toString(16)})...`);
  const start = Date.now();
  await exchange(transport, cfg.KEYGEN, 0, 0);
  const elapsed = (Date.now() - start) / 1000;
  console.log(`  keygen elapsed: ${elapsed.toFixed(1)} s`);

  console.log(`  reading pk via GET_PK (INS=0x${cfg.GET_PK.toString(16)}, ${cfg.PK_SIZE} B)...`);
  const pk = await getPkChunked(transport, cfg.GET_PK, cfg.PK_SIZE);
  if (pk.length !== cfg.PK_SIZE) {
    throw new Error(`pk length ${pk.length} != expected ${cfg.PK_SIZE}`);
  }
  const sha = crypto.createHash('sha256').update(pk).digest('hex');
  console.log(`  pk SHA-256: ${sha}`);
  return { label: cfg.LABEL, sha, size: cfg.PK_SIZE };
}


async function main() {
  console.log('═══ Streaming variant — pk reference dumper ═══');
  console.log('Mnemonic expected: "yellow ×12", no passphrase');
  console.log('Device must be unlocked, streaming-variant app open.');

  const transport = await TransportNodeHid.create();

  const r1024 = await dumpVariant(transport, STREAMING_1024);
  const r512  = await dumpVariant(transport, STREAMING_512);

  console.log('\n═══ COPY-PASTE BLOCK (send this back) ═══');
  console.log('');
  console.log(`/* Reference pk SHA-256 — produced by streaming variant`);
  console.log(` * with mnemonic "yellow ×12". Identical across streaming`);
  console.log(` * and flash variants by construction (same Zf(keygen)). */`);
  console.log(`const REF_PK_SHA256_1024 = '${r1024.sha}';`);
  console.log(`const REF_PK_SHA256_512  = '${r512.sha}';`);
  console.log('');
  console.log('═══════════════════════════════════════════════');

  await transport.close();
}

main().catch((e) => {
  console.error('FATAL:', e.message || e);
  process.exit(1);
});
