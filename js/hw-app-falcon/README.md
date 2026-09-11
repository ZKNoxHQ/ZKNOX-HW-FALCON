# @zknox/hw-app-falcon

Ledger "hw-app" for the ZKNOX Falcon signer (ZKNOX-HW-FALCON, low-RAM core). Transport-agnostic
(`@ledgerhq/hw-transport-node-hid`, `-webhid`, `-webusb`, `-web-ble`).

```js
const Transport = require('@ledgerhq/hw-transport-node-hid').default;
const FalconApp = require('@zknox/hw-app-falcon');

const app = new FalconApp(await Transport.create());
const { h, coefficients } = await app.getPublicKey({ logn: 9 });      // Falcon-512 public key, raw h
const { salt, s2, timings } = await app.signHash({ logn: 9, hash });  // hash: 32 bytes (Buffer or hex)
```

- `getPublicKey({ logn })`: h in coefficient form (2n bytes, uint16 LE) and as `Uint16Array`.
- `signHash({ logn, hash, seed? })`: Falcon Round 3 signature of a 32-byte digest, salt (40 bytes) and raw s2
  (`Int16Array`). The signing seed comes from the device TRNG; `seed` is for tests and KATs only.
- `generateKey({ logn, force })`: makes the key available (implicit otherwise), useful to time the key generation.
- Errors: `FalconAppError` with `statusCode` (0x6A80 state error, 0x6A86 bad P1/P2, 0x6A87 bad length, ...).

The device signs digests and returns raw material; encodings for a given verifier (ETHFALCON calldata,
NTT form of h, smart-account signature formats) live in the verifier and account packages, not here.
Verification: c = hash_to_point(SHAKE256(salt ‖ hash)), s1 = c − s2·h mod q, ‖(s1, s2)‖² ≤ 34034726 (512) /
70265242 (1024).

Tests:
- `npm test`: mock transport reproducing the APDU state machine, no device needed.
- `FALCON_DEVICE=1 npm run test:device` (or `npm run test:device`): real device with the Falcon app open. Checks the
  app identity, both degrees (key, forced keygen timing, TRNG signatures verified on the host) and, with the
  yellow x12 mnemonic, the seeded KATs of `test/kat/yellow12.json`, which also identify the sampler build loaded
  (plain or SCA-protected). Skipped when no device answers.
