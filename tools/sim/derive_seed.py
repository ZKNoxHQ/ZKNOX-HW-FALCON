import hashlib, hmac, struct, sys, unicodedata
mnemonic = " ".join(["yellow"] * 12)
bip39_seed = hashlib.pbkdf2_hmac("sha512", unicodedata.normalize("NFKD", mnemonic).encode(),
                                 b"mnemonic", 2048, 64)
def slip10(seed_key: bytes, path):
    I = hmac.new(seed_key, bip39_seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for idx in path:
        idx |= 0x80000000
        I = hmac.new(c, b"\x00" + k + struct.pack(">I", idx), hashlib.sha512).digest()
        k, c = I[:32], I[32:]
    return k
path = [44, 9004, 0, 0, 0]
for label, fn in ((b"Falcon-1024 seed", "seed_1024.bin"), (b"Falcon-512 seed", "seed_512.bin")):
    s = slip10(label, path)
    open(fn, "wb").write(s)
    print(fn, s.hex())
