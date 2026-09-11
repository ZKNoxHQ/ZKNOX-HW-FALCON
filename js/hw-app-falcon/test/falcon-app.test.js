'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const FalconApp = require('..');
const MockTransport = require('./mock-transport');

function fixture(logn) {
  const n = 1 << logn;
  const h = Buffer.alloc(2 * n); for (let i = 0; i < n; i++) h.writeUInt16LE(i * 37 % 12289, 2 * i);
  const s2Raw = Buffer.alloc(2 * n); for (let i = 0; i < n; i++) s2Raw.writeInt16LE(((i * 91) % 601) - 300, 2 * i);
  return { logn, h, salt: crypto.randomBytes(40), s2Raw };
}

for (const logn of [9, 10]) {
  test(`getPublicKey reassembles the ${2 << logn}-byte key from 255-byte chunks (logn=${logn})`, async () => {
    const fx = fixture(logn); const app = new FalconApp(new MockTransport(fx));
    const pk = await app.getPublicKey({ logn });
    assert.equal(pk.n, 1 << logn);
    assert.deepEqual(pk.h, fx.h);
    assert.equal(pk.coefficients[3], fx.h.readUInt16LE(6));
    assert.equal(app.transport.calls.filter(c => c.ins === 0x51).length, Math.ceil((2 << logn) / 255));
  });
  test(`signHash runs INIT/FEED_MSG/GEN_SEED/SIGN_ALL/GET_NONCE/GET_SIG and parses s2 as int16 (logn=${logn})`, async () => {
    const fx = fixture(logn); const app = new FalconApp(new MockTransport(fx));
    const sig = await app.signHash({ logn, hash: crypto.randomBytes(32) });
    assert.deepEqual(sig.salt, fx.salt);
    assert.deepEqual(sig.s2Raw, fx.s2Raw);
    assert.equal(sig.s2[7], fx.s2Raw.readInt16LE(14));
    const p1s = app.transport.calls.filter(c => c.ins === 0x53).map(c => c.p1);
    assert.deepEqual(p1s, [0x00, 0x06, 0x09, 0x10, 0x91]);
  });
}

test('seeded signing uses FEED_SEED instead of GEN_SEED', async () => {
  const fx = fixture(9); const app = new FalconApp(new MockTransport(fx));
  await app.signHash({ logn: 9, hash: '0x' + '11'.repeat(32), seed: Buffer.alloc(40, 0xa0) });
  assert.deepEqual(app.transport.calls.filter(c => c.ins === 0x53).map(c => c.p1), [0x00, 0x06, 0x08, 0x10, 0x91]);
});

test('input validation', async () => {
  const fx = fixture(9); const app = new FalconApp(new MockTransport(fx));
  await assert.rejects(app.signHash({ logn: 9, hash: Buffer.alloc(31) }), /hash must be 32 bytes/);
  await assert.rejects(app.signHash({ logn: 11, hash: Buffer.alloc(32) }), /logn must be 9/);
  await assert.rejects(app.getPublicKey({ logn: 10 }), (e) => e instanceof FalconApp.FalconAppError && e.statusCode === 0x6a86);
});

test('status words become FalconAppError with the code', async () => {
  const fx = fixture(9); const t = new MockTransport(fx); const app = new FalconApp(t);
  // GET_SIG before any signature: 0x6A80
  await assert.rejects(app._pull(0x54, 9), (e) => e.statusCode === 0x6a80 && /state error/.test(e.message));
  const v = await app.getVersion(); assert.deepEqual(v, { major: 1, minor: 2, patch: 3 });
  assert.equal(await app.getAppName(), 'Falcon');
});
