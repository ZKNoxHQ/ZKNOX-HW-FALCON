# Host test kit

- `falcon-lowram-test.js` — device test of the low-RAM Falcon core (INS 0x50..0x54): KEYGEN, GET_PK, N signatures
  (TRNG or seeded), GET_NONCE, GET_SIG, `verify_raw` on the host, per-APDU timings.
  `node falcon-lowram-test.js 10 5`, `node falcon-lowram-test.js 9 2 --seeded`.
- `falcon512-verify.js`, `falcon1024-verify.js` — Falcon Round 3 verification in pure JS (`hashToPoint`, `verifyRaw`),
  bounds 34034726 / 70265242. `falcon1024-kat-verify.js` + `kat_validation/` validate the verifier against the
  PQClean Falcon-1024 KATs (`node kat_validation/validate_pqclean_kat.js`).
- Dependencies: `npm install` (`@ledgerhq/hw-transport-node-hid`).

The v0.7.0 streaming harness (keygen-expand wire, 12-step sign) is archived in `../legacy/js/`.
