# Host test kit

- `hw-app-falcon/` — `@zknox/hw-app-falcon`, the Ledger hw-app for this signer (transport-agnostic):
  `getPublicKey({ logn })`, `signHash({ logn, hash, seed? })`, `generateKey({ logn, force })`. Unit tests on a
  mock transport: `npm test`. Verifier-specific encodings (ETHFALCON calldata, NTT form of h, smart-account
  formats) are out of its scope by design.
- `falcon-lowram-test.js` — device test on top of the hw-app: key, N signatures (TRNG or seeded), `verify_raw`
  on the host, per-APDU timings. `node falcon-lowram-test.js 10 5`, `node falcon-lowram-test.js 9 2 --seeded`,
  `FALCON_MOCK=1 node falcon-lowram-test.js 9 1` (no device, exercises the client only).
- `falcon512-verify.js`, `falcon1024-verify.js` — Falcon Round 3 verification in pure JS (`hashToPoint`, `verifyRaw`),
  bounds 34034726 / 70265242. `falcon1024-kat-verify.js` + `kat_validation/` validate the verifier against the
  PQClean Falcon-1024 KATs (`node kat_validation/validate_pqclean_kat.js`).
- Dependencies: `npm install`.
