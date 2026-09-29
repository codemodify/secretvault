#!/usr/bin/env python3
"""Encrypts and decrypts a LUKS2 image's data sectors with Python's
cryptography package, following dm-crypt's aes-xts-plain64 rather than our
Go code: each sector is one XTS data unit, whose tweak is the number of the
512-byte sector it starts at plus the segment's iv_tweak, as a 128-bit
little-endian integer (LUKS2 counts 512-byte sectors whatever its sector
size). A cross-check of svluks.Volume:

    check_xts.py decrypt IMAGE KEYHEX OFFSET SECTORSIZE IVTWEAK AT LENGTH OUT
    check_xts.py encrypt IMAGE KEYHEX OFFSET SECTORSIZE IVTWEAK AT IN

OFFSET is where the data starts in IMAGE, AT a sector-aligned position in
the data; decrypt writes LENGTH bytes of plaintext to OUT, and encrypt
writes IN's bytes (whole sectors) into IMAGE.
"""
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

mode, image, key = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3])
offset, ss, tweak, at = (int(a) for a in sys.argv[4:8])
assert at % ss == 0, "AT is not sector-aligned"


def xts(sector_pos, data, encrypt):
    iv = (tweak + sector_pos // 512).to_bytes(16, "little")
    c = Cipher(algorithms.AES(key), modes.XTS(iv))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


with open(image, "r+b") as f:
    if mode == "decrypt":
        length, out = int(sys.argv[8]), sys.argv[9]
        f.seek(offset + at)
        data = f.read((length + ss - 1) // ss * ss)
        plain = b"".join(xts(at + i, data[i:i + ss], False) for i in range(0, len(data), ss))
        open(out, "wb").write(plain[:length])
    elif mode == "encrypt":
        plain = open(sys.argv[8], "rb").read()
        assert len(plain) % ss == 0, "IN is not whole sectors"
        f.seek(offset + at)
        f.write(b"".join(xts(at + i, plain[i:i + ss], True) for i in range(0, len(plain), ss)))
    else:
        sys.exit("mode is decrypt or encrypt")
print("ok")
