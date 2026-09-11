'use strict';
/**
 * @zknox/hw-app-falcon — Ledger "hw-app" wrapper for the ZKNOX Falcon signer (ZKNOX-HW-FALCON,
 * low-RAM core, INS 0x50..0x54). Transport-agnostic: works with any @ledgerhq/hw-transport
 * (node-hid, webhid, webusb, ble).
 *
 * The device signs 32-byte digests and knows nothing about Ethereum: this package returns the raw
 * public key h (uint16 coefficients) and the raw signature (40-byte salt, int16 s2). Verifier-specific
 * encodings (ETHFALCON calldata, NTT of h, smart-account signature formats) belong to the verifier
 * and account packages.
 *
 * APDU contract (CLA 0xE0, P2 = logn: 9 = Falcon-512, 10 = Falcon-1024):
 *   0x50 KEYGEN   P1=0 (P1=1 forces a fresh key generation)   -> h[0..255)
 *   0x51 GET_PK   P1=chunk index                                -> 255-byte chunks of h (2n bytes)
 *   0x53 SIGN     P1=0x00 INIT | 0x06 FEED_MSG (32 B) | 0x08 FEED_SEED (40 B, test only) |
 *                 0x09 GEN_SEED (TRNG) | 0x10 SIGN_ALL | 0x91 GET_NONCE
 *   0x54 GET_SIG  P1=chunk index                                -> 255-byte chunks of s2 (int16, 2n bytes)
 */

const CLA = 0xe0;
const INS = Object.freeze({
  GET_VERSION: 0x03,
  GET_APP_NAME: 0x04,
  KEYGEN: 0x50,
  GET_PK: 0x51,
  SIGN: 0x53,
  GET_SIG: 0x54,
});
const P1_SIGN = Object.freeze({
  INIT: 0x00,
  FEED_MSG: 0x06,
  FEED_SEED: 0x08,
  GEN_SEED: 0x09,
  SIGN_ALL: 0x10,
  GET_NONCE: 0x91,
});
const SW = Object.freeze({
  OK: 0x9000,
  INCORRECT_DATA: 0x6a80,
  INCORRECT_P1_P2: 0x6a86,
  WRONG_DATA_LENGTH: 0x6a87,
  CONDITIONS_NOT_SATISFIED: 0x6985,
  INVALID_INS: 0x6d00,
  INVALID_CLA: 0x6e00,
});
const SW_MESSAGES = Object.freeze({
  [SW.INCORRECT_DATA]: 'state error: no key for this seed, message or seed not fed, or signature not available',
  [SW.INCORRECT_P1_P2]: 'bad P1/P2 (unsupported logn or chunk index)',
  [SW.WRONG_DATA_LENGTH]: 'bad data length (message must be 32 bytes, seed 40 bytes)',
  [SW.CONDITIONS_NOT_SATISFIED]: 'conditions not satisfied (app locked or action rejected on the device)',
  [SW.INVALID_INS]: 'unknown instruction: is the Falcon app open?',
  [SW.INVALID_CLA]: 'wrong CLA: is the Falcon app open?',
});
const SALT_LEN = 40;
const DIGEST_LEN = 32;
const SEED_LEN = 40;
const CHUNK = 255;

class FalconAppError extends Error {
  constructor(statusCode, ins, p1) {
    const hex = statusCode.toString(16).padStart(4, '0');
    super(`Falcon app: INS 0x${ins.toString(16)} P1 0x${p1.toString(16)} failed with sw=0x${hex}` +
          (SW_MESSAGES[statusCode] ? ` (${SW_MESSAGES[statusCode]})` : ''));
    this.name = 'FalconAppError';
    this.statusCode = statusCode;
    this.ins = ins;
    this.p1 = p1;
  }
}

function checkLogn(logn) {
  if (logn !== 9 && logn !== 10) throw new TypeError('logn must be 9 (Falcon-512) or 10 (Falcon-1024)');
  return logn;
}
function toBuffer(x, len, what) {
  const b = Buffer.isBuffer(x) ? x : Buffer.from(typeof x === 'string' ? x.replace(/^0x/, '') : x, typeof x === 'string' ? 'hex' : undefined);
  if (b.length !== len) throw new TypeError(`${what} must be ${len} bytes, got ${b.length}`);
  return b;
}

/**
 * Falcon signer on a Ledger device.
 *
 * @example
 *   const Transport = require('@ledgerhq/hw-transport-node-hid').default;
 *   const FalconApp = require('@zknox/hw-app-falcon');
 *   const app = new FalconApp(await Transport.create());
 *   const { h } = await app.getPublicKey({ logn: 9 });
 *   const { salt, s2 } = await app.signHash({ logn: 9, hash: digest32 });
 */
class FalconApp {
  /**
   * @param {import('@ledgerhq/hw-transport').default} transport
   * @param {string} [scrambleKey] key used by the transport to scramble APDUs (Ledger convention)
   */
  constructor(transport, scrambleKey = 'FALCON') {
    this.transport = transport;
    if (typeof transport.decorateAppAPIMethods === 'function') {
      transport.decorateAppAPIMethods(this, ['getVersion', 'getAppName', 'generateKey', 'getPublicKey', 'signHash'], scrambleKey);
    }
  }

  /** @private raw APDU exchange; throws FalconAppError on a non-0x9000 status word */
  async _send(ins, p1, p2, data = Buffer.alloc(0)) {
    const r = await this.transport.send(CLA, ins, p1, p2, data, [SW.OK, SW.INCORRECT_DATA, SW.INCORRECT_P1_P2,
      SW.WRONG_DATA_LENGTH, SW.CONDITIONS_NOT_SATISFIED, SW.INVALID_INS, SW.INVALID_CLA]);
    const sw = r.readUInt16BE(r.length - 2);
    if (sw !== SW.OK) throw new FalconAppError(sw, ins, p1);
    return r.subarray(0, r.length - 2);
  }

  /** @private pull a 2n-byte value in 255-byte chunks (GET_PK / GET_SIG) */
  async _pull(ins, logn) {
    const total = 2 << logn;
    const parts = [];
    let got = 0;
    for (let i = 0; got < total; i++) {
      const c = await this._send(ins, i, logn);
      if (c.length === 0) throw new Error(`Falcon app: empty chunk ${i} from INS 0x${ins.toString(16)}`);
      parts.push(c);
      got += c.length;
    }
    return Buffer.concat(parts, total);
  }

  /** App version as reported by GET_VERSION. @returns {Promise<{major:number, minor:number, patch:number}>} */
  async getVersion() {
    const r = await this._send(INS.GET_VERSION, 0, 0);
    return { major: r[0], minor: r[1], patch: r[2] };
  }

  /** App name as reported by GET_APP_NAME. @returns {Promise<string>} */
  async getAppName() {
    return (await this._send(INS.GET_APP_NAME, 0, 0)).toString('ascii');
  }

  /**
   * Makes the key of a degree available on the device (deterministic from the device seed; regenerated
   * from the SLIP-10 seed on first use in a session, or on `force`). Returns the first 255 bytes of h.
   * Mostly useful to measure the key generation; getPublicKey() and signHash() trigger it implicitly.
   * @param {{logn?: 9|10, force?: boolean}} [opts]
   * @returns {Promise<{logn: number, head: Buffer, ms: number}>}
   */
  async generateKey({ logn = 10, force = false } = {}) {
    checkLogn(logn);
    const t0 = Date.now();
    const head = await this._send(INS.KEYGEN, force ? 1 : 0, logn);
    return { logn, head, ms: Date.now() - t0 };
  }

  /**
   * Public key h of the degree, coefficient form: 2n bytes, uint16 little-endian (device host order).
   * @param {{logn?: 9|10}} [opts]
   * @returns {Promise<{logn: number, n: number, h: Buffer, coefficients: Uint16Array}>}
   */
  async getPublicKey({ logn = 10 } = {}) {
    checkLogn(logn);
    const h = await this._pull(INS.GET_PK, logn);
    const n = 1 << logn;
    const coefficients = new Uint16Array(n);
    for (let i = 0; i < n; i++) coefficients[i] = h.readUInt16LE(2 * i);
    return { logn, n, h, coefficients };
  }

  /**
   * Signs a 32-byte digest with Falcon (Round 3): c = hash_to_point(SHAKE256(salt || hash)),
   * returns the 40-byte salt (nonce) and the raw s2 polynomial (int16 little-endian, 2n bytes).
   * The signing seed comes from the device TRNG; `seed` (40 bytes) is for tests and KATs only: with
   * the same key, hash and seed the device returns byte-identical signatures.
   * @param {{logn?: 9|10, hash: Buffer|string, seed?: Buffer|string}} opts
   * @returns {Promise<{logn: number, n: number, salt: Buffer, s2Raw: Buffer, s2: Int16Array, timings: {signMs: number, totalMs: number}}>}
   */
  async signHash({ logn = 10, hash, seed } = {}) {
    checkLogn(logn);
    const digest = toBuffer(hash, DIGEST_LEN, 'hash');
    const t0 = Date.now();
    await this._send(INS.SIGN, P1_SIGN.INIT, logn);
    await this._send(INS.SIGN, P1_SIGN.FEED_MSG, logn, digest);
    if (seed !== undefined) await this._send(INS.SIGN, P1_SIGN.FEED_SEED, logn, toBuffer(seed, SEED_LEN, 'seed'));
    else await this._send(INS.SIGN, P1_SIGN.GEN_SEED, logn);
    const t1 = Date.now();
    await this._send(INS.SIGN, P1_SIGN.SIGN_ALL, logn);
    const signMs = Date.now() - t1;
    const salt = await this._send(INS.SIGN, P1_SIGN.GET_NONCE, logn);
    if (salt.length !== SALT_LEN) throw new Error(`Falcon app: nonce of ${salt.length} bytes`);
    const s2Raw = await this._pull(INS.GET_SIG, logn);
    const n = 1 << logn;
    const s2 = new Int16Array(n);
    for (let i = 0; i < n; i++) s2[i] = s2Raw.readInt16LE(2 * i);
    return { logn, n, salt: Buffer.from(salt), s2Raw, s2, timings: { signMs, totalMs: Date.now() - t0 } };
  }
}

FalconApp.CLA = CLA;
FalconApp.INS = INS;
FalconApp.P1_SIGN = P1_SIGN;
FalconApp.SW = SW;
FalconApp.SALT_LEN = SALT_LEN;
FalconApp.DIGEST_LEN = DIGEST_LEN;
FalconApp.FalconAppError = FalconAppError;

module.exports = FalconApp;
module.exports.default = FalconApp;
module.exports.FalconAppError = FalconAppError;
