#!/usr/bin/env python3
"""Reads a KDBX 4 file written by ExportKDBX (AES-256-CBC, Argon2id, gzip,
ChaCha20 inner stream) with Python's cryptography package, following
KeePass's format description rather than our Go code, and prints its
groups and entries with secrets masked. A cross-check of the writer:

    secretvault export kdbx out.kdbx --new-passphrase-file pass
    python3 check_kdbx_export.py out.kdbx pass
"""
import base64, gzip, hashlib, hmac, struct, sys
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

data = open(sys.argv[1], "rb").read()
password = open(sys.argv[2], "rb").read().rstrip(b"\n")
sig1, sig2, ver = struct.unpack("<III", data[:12])
assert (sig1, sig2) == (0x9AA2D903, 0xB54BFB67), "signature"
print("version %d.%d" % (ver >> 16, ver & 0xFFFF))
p, fields = 12, {}
while True:
    fid, size = struct.unpack("<BI", data[p:p + 5]); p += 5
    fields[fid] = data[p:p + size]; p += size
    if fid == 0:
        break
header = data[:p]
assert hashlib.sha256(header).digest() == data[p:p + 32], "header hash"
vd, q, kdf = fields[11], 2, {}
while vd[q] != 0:
    t = vd[q]; kl = struct.unpack("<I", vd[q + 1:q + 5])[0]; k = vd[q + 5:q + 5 + kl]
    vl = struct.unpack("<I", vd[q + 5 + kl:q + 9 + kl])[0]; v = vd[q + 9 + kl:q + 9 + kl + vl]
    kdf[k] = v; q += 9 + kl + vl
assert kdf[b"$UUID"].hex() == "9e298b1956db4773b23dfc3ec6f0a1e6", "argon2id"
it, mem, par = struct.unpack("<Q", kdf[b"I"])[0], struct.unpack("<Q", kdf[b"M"])[0], struct.unpack("<I", kdf[b"P"])[0]
print("argon2id t=%d m=%dKiB p=%d cipher=%s" % (it, mem // 1024, par, fields[2].hex()))
composite = hashlib.sha256(hashlib.sha256(password).digest()).digest()
transformed = Argon2id(salt=kdf[b"S"], length=32, iterations=it, lanes=par, memory_cost=mem // 1024).derive(composite)
seed = fields[4]
hmac_key = hashlib.sha512(seed + transformed + b"\x01").digest()
bk = lambda i: hashlib.sha512(struct.pack("<Q", i) + hmac_key).digest()
assert hmac.new(bk(0xFFFFFFFFFFFFFFFF), header, hashlib.sha256).digest() == data[p + 32:p + 64], "header hmac"
p += 64; ct = b""; i = 0
while True:
    mac = data[p:p + 32]; size = struct.unpack("<I", data[p + 32:p + 36])[0]; blk = data[p + 36:p + 36 + size]
    assert hmac.new(bk(i), struct.pack("<QI", i, size) + blk, hashlib.sha256).digest() == mac, "block %d" % i
    p += 36 + size; i += 1
    if size == 0:
        break
    ct += blk
d = Cipher(algorithms.AES(hashlib.sha256(seed + transformed).digest()), modes.CBC(fields[7])).decryptor()
pt = d.update(ct) + d.finalize()
u = padding.PKCS7(128).unpadder(); pt = u.update(pt) + u.finalize()
if struct.unpack("<I", fields[3])[0] == 1:
    pt = gzip.decompress(pt)
q, inner = 0, {}
while True:
    t, size = struct.unpack("<BI", pt[q:q + 5]); inner[t] = pt[q + 5:q + 5 + size]; q += 5 + size
    if t == 0:
        break
assert struct.unpack("<I", inner[1])[0] == 3, "chacha20 inner stream"
h = hashlib.sha512(inner[2]).digest()
stream = Cipher(algorithms.ChaCha20(h[:32], b"\x00" * 4 + h[32:44]), None).encryptor()
root = ET.fromstring(pt[q:])
def walk(g, path):
    for e in g:
        if e.tag == "Entry":
            vals = {}
            for s in e.findall("String"):
                v = s.find("Value")
                txt = v.text or ""
                if v.get("Protected") == "True":
                    txt = stream.update(base64.b64decode(txt)).decode("utf-8", "replace")
                vals[s.find("Key").text] = txt
            print("/".join(path + [vals["Title"]]), {k: ("***" if k in ("Password", "otp") else v) for k, v in vals.items() if v})
        elif e.tag == "Group":
            walk(e, path + [e.find("Name").text])
top = root.find("Root").find("Group")
walk(top, [])
print("ok")
