'use strict';
/* Minimal in-memory transport reproducing the app's APDU state machine and status words. */
const crypto = require('crypto');
class MockTransport {
  constructor({ logn = 9, h, salt, s2Raw } = {}) {
    this.logn = logn; this.h = h; this.salt = salt; this.s2Raw = s2Raw;
    this.msgReady = false; this.seedReady = false; this.sigReady = 0; this.calls = [];
  }
  decorateAppAPIMethods() {}
  async send(cla, ins, p1, p2, data = Buffer.alloc(0)) {
    this.calls.push({ ins, p1, p2, len: data.length });
    const ok = (payload = Buffer.alloc(0)) => Buffer.concat([payload, Buffer.from([0x90, 0x00])]);
    const sw = (code) => Buffer.from([code >> 8, code & 0xff]);
    if (cla !== 0xe0) return sw(0x6e00);
    if (ins === 0x03) return ok(Buffer.from([1, 2, 3]));
    if (ins === 0x04) return ok(Buffer.from('Falcon'));
    if (ins >= 0x50 && p2 !== this.logn) return sw(0x6a86);
    const n = 1 << this.logn;
    switch (ins) {
      case 0x50: return p1 > 1 ? sw(0x6a86) : ok(this.h.subarray(0, 255));
      case 0x51: { const off = p1 * 255; if (off >= 2 * n) return sw(0x6a86); return ok(this.h.subarray(off, Math.min(off + 255, 2 * n))); }
      case 0x53:
        switch (p1) {
          case 0x00: this.msgReady = this.seedReady = false; this.sigReady = 0; return ok();
          case 0x06: if (data.length !== 32) return sw(0x6a87); this.msgReady = true; return ok();
          case 0x08: if (data.length !== 40) return sw(0x6a87); this.seedReady = true; return ok();
          case 0x09: this.seedReady = true; return ok();
          case 0x10: if (!this.msgReady || !this.seedReady) return sw(0x6a80); this.sigReady = this.logn; this.seedReady = false; return ok();
          case 0x91: return this.sigReady ? ok(this.salt) : sw(0x6a80);
          default: return sw(0x6a86);
        }
      case 0x54: { if (!this.sigReady) return sw(0x6a80); const off = p1 * 255; if (off >= 2 * n) return sw(0x6a86); return ok(this.s2Raw.subarray(off, Math.min(off + 255, 2 * n))); }
      default: return sw(0x6d00);
    }
  }
}
module.exports = MockTransport;
