"""Checks the golden signed sv1-nist revision against docs/format.md, with
Python's cryptography package: an implementation independent of svformat.

    python3 svformat/testdata/revision-signed-check.py svformat/testdata/revision-signed-sv1-nist.hex

It opens the revision (AES-256-GCM under HKDF-derived keys: sv1-nist, which
Python has; sv1-modern's XChaCha20 it has not), rebuilds what the signature
signs from the spec, verifies the signature with the golden key, and checks
that signing again gives the same bytes. Not run by go test."""
import hashlib, hmac, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def hkdf(ikm, salt, info, n):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)


def derive(key, salt, label, n):
    return hkdf(key, salt, b"secretvault " + label, n)


def nist_open(key, msg, aad):
    salt, ct = msg[:32], msg[32:]
    okm = hkdf(key, salt, b"secretvault sv1-nist message", 44)
    return AESGCM(okm[:32]).decrypt(okm[32:44], ct, aad)


def tlv(fields):
    out = b""
    for tag, v in fields:
        out += bytes([tag]) + struct.pack(">H", len(v)) + v
    return out


def untlv(b):
    fields = []
    while b:
        tag, n = b[0], struct.unpack(">H", b[1:3])[0]
        fields.append((tag, b[3:3 + n]))
        b = b[3 + n:]
    return fields


path = sys.argv[1]
f = bytes.fromhex(open(path).read().strip())
assert f[:4] == b"SVR1" and f[4] == 2 and f[5] == 0
n = struct.unpack(">H", f[6:8])[0]
prefix, body = f[:8 + n], f[8 + n:]
fields = dict(untlv(f[8:8 + n]))
vault, obj, epoch = fields[1], fields[2], fields[3]
wrap = bytes([0x11]) * 32
dek = nist_open(wrap, fields[6], b"secretvault sv1 dek" + vault + obj + epoch)
assert dek == bytes([0x22]) * 32
padded = nist_open(dek, body, prefix)
plen = struct.unpack(">I", padded[:4])[0]
payload = padded[4:4 + plen]
assert not any(padded[4 + plen:])

sig = fields[0x82]
alg, kid, s = sig[0], sig[1:17], sig[17:]
assert alg == 1 and len(s) == 64
unsigned_hdr = tlv([(t, v) for t, v in untlv(f[8:8 + n]) if t != 0x82])
unsigned_prefix = b"SVR1" + bytes([2, 0]) + struct.pack(">H", len(unsigned_hdr)) + unsigned_hdr
commit = hmac.new(derive(dek, vault, b"sv1 revision commit", 32), payload, hashlib.sha256).digest()
signed = b"secretvault sv1 revision signature" + tlv([
    (1, bytes([alg])), (2, kid), (3, hashlib.sha256(unsigned_prefix).digest()), (4, commit)])

key = Ed25519PrivateKey.from_private_bytes(bytes([0x33]) * 32)
pub = key.public_key()
raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
assert kid == hashlib.sha256(b"secretvault sv1 device key" + bytes([1]) + raw).digest()[:16]
pub.verify(s, signed)  # raises if bad
assert key.sign(signed) == s  # Ed25519 is deterministic
print("ok:", payload.decode())
