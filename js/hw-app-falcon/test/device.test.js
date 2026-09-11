'use strict';
/*
 * Device test: runs against a real Ledger with the Falcon app open (FALCON_DEVICE=1 npm run test:device).
 * Skipped when no device is reachable. Checks the app identity, both degrees (public key, TRNG signatures
 * verified on the host, keygen timing) and, with the yellow x12 mnemonic, the KATs of tools/sim: public
 * key hashes and seeded signatures, which also tell which sampler build is loaded.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const path = require('path');
const FalconApp = require('..');
const kat = require('./kat/yellow12.json');

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const wantDevice = !!process.env.FALCON_DEVICE;
let transport = null;

async function openDevice() {
  if (transport) return transport;
  const Transport = require('@ledgerhq/hw-transport-node-hid').default;
  transport = await Promise.race([Transport.create(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000))]);
  return transport;
}

test('device: app identity', { skip: !wantDevice && 'set FALCON_DEVICE=1 with the Falcon app open' }, async (t) => {
  let app;
  try { app = new FalconApp(await openDevice()); } catch (e) { t.skip(`no device: ${e.message}`); return; }
  const name = await app.getAppName();
  const v = await app.getVersion();
  t.diagnostic(`app ${name} v${v.major}.${v.minor}.${v.patch}`);
  assert.match(name, /falcon/i);
});

for (const logn of [9, 10]) {
  const n = 1 << logn;
  const verify = require(path.join(__dirname, '..', '..', logn === 9 ? 'falcon512-verify.js' : 'falcon1024-verify.js'));

  test(`device: Falcon-${n} key, keygen timing, TRNG signatures verify`, { skip: !wantDevice && 'FALCON_DEVICE=1', timeout: 120000 }, async (t) => {
    let app;
    try { app = new FalconApp(await openDevice()); } catch (e) { t.skip(`no device: ${e.message}`); return; }
    const kg = await app.generateKey({ logn, force: true });
    t.diagnostic(`keygen Falcon-${n}: ${kg.ms} ms (forced)`);
    assert.equal(kg.head.length, 255);
    const pk = await app.getPublicKey({ logn });
    assert.equal(pk.h.length, 2 * n);
    assert.deepEqual(pk.h.subarray(0, 255), kg.head);
    const pkHash = sha256(pk.h);
    t.diagnostic(`pk sha256 ${pkHash}${pkHash === kat.pk_sha256[String(logn)] ? ' (yellow x12 KAT match)' : ''}`);
    for (let i = 0; i < 2; i++) {
      const hash = crypto.randomBytes(32);
      const sig = await app.signHash({ logn, hash });
      assert.equal(sig.salt.length, 40);
      assert.equal(sig.s2Raw.length, 2 * n);
      const ok = verify.verifyRaw(verify.hashToPoint(sig.salt, hash), sig.s2Raw, pk.h);
      t.diagnostic(`signature ${i}: SIGN_ALL ${sig.timings.signMs} ms, total ${sig.timings.totalMs} ms, ${ok ? 'valid' : 'INVALID'}`);
      assert.ok(ok, `Falcon-${n} signature ${i} does not verify`);
    }
  });

  test(`device: Falcon-${n} seeded KAT (yellow x12) and sampler build detection`, { skip: !wantDevice && 'FALCON_DEVICE=1', timeout: 120000 }, async (t) => {
    let app;
    try { app = new FalconApp(await openDevice()); } catch (e) { t.skip(`no device: ${e.message}`); return; }
    const pk = await app.getPublicKey({ logn });
    if (sha256(pk.h) !== kat.pk_sha256[String(logn)]) { t.skip('device mnemonic is not yellow x12: KAT not applicable'); return; }
    const hashes = [];
    for (let i = 0; i < 2; i++) {
      const hash = crypto.createHash('sha256').update(`falcon-core-test ${i}`).digest();
      const sig = await app.signHash({ logn, hash, seed: Buffer.alloc(40, 0xa0 + i) });
      hashes.push(sha256(sig.s2Raw));
    }
    const build = Object.keys(kat.s2_sha256).find((b) => kat.s2_sha256[b][String(logn)].every((h, i) => h === hashes[i]));
    t.diagnostic(`seeded signatures ${hashes.map((h) => h.slice(0, 16) + '…').join(', ')} -> sampler build: ${build || 'UNKNOWN'}`);
    assert.ok(build, 'seeded signatures match neither the plain nor the protected sampler vectors (firmware or key mismatch)');
  });
}

test.after(async () => { if (transport && typeof transport.close === 'function') await transport.close(); });
