#!/usr/bin/env python3
"""Builds the encrypted import fixtures in this directory, independently of
secretvault's own Go code, so the readers are not tested only against their
own writer.

The crypto here is Python's `cryptography` package (OpenSSL) for AES,
ChaCha20, PBKDF2, HKDF, HMAC, scrypt, AES-GCM and Argon2id; the reference
Argon2 command-line tool (phc-winner-argon2's `argon2`) for Argon2d; and a
Salsa20 written below from Bernstein's specification, checked against the
eSTREAM test vector. The KDBX files are assembled from KeePass's published
format description (https://keepass.info/help/kb/kdbx.html and
https://keepass.info/help/kb/kdbx_4.1.html), the Bitwarden export from
Bitwarden's exporter source, the Aegis vault from Aegis's docs/vault.md.

Run it from this directory:  python3 make_fixtures.py
The outputs are random each time (seeds, IVs); the tests only need them to
decrypt to the contents written here.
"""

import base64
import gzip
import hashlib
import hmac
import json
import os
import struct
import subprocess
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding

PASSWORD = b"correct horse battery staple"

# ---------------------------------------------------------------- Salsa20


def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _salsa_block(key, nonce, counter):
    c = b"expand 32-byte k"
    k = struct.unpack("<8I", key)
    const = struct.unpack("<4I", c)
    n = struct.unpack("<2I", nonce)
    ctr = struct.unpack("<2I", struct.pack("<Q", counter))
    x = [const[0], k[0], k[1], k[2], k[3], const[1], n[0], n[1],
         ctr[0], ctr[1], const[2], k[4], k[5], k[6], k[7], const[3]]
    z = list(x)

    def qr(a, b, c_, d):
        z[b] ^= _rotl((z[a] + z[d]) & 0xFFFFFFFF, 7)
        z[c_] ^= _rotl((z[b] + z[a]) & 0xFFFFFFFF, 9)
        z[d] ^= _rotl((z[c_] + z[b]) & 0xFFFFFFFF, 13)
        z[a] ^= _rotl((z[d] + z[c_]) & 0xFFFFFFFF, 18)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)
        qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)
    return struct.pack("<16I", *[(z[i] + x[i]) & 0xFFFFFFFF for i in range(16)])


class Salsa20Stream:
    def __init__(self, key, nonce):
        self.key, self.nonce, self.counter, self.buf = key, nonce, 0, b""

    def xor(self, data):
        while len(self.buf) < len(data):
            self.buf += _salsa_block(self.key, self.nonce, self.counter)
            self.counter += 1
        out = bytes(a ^ b for a, b in zip(data, self.buf))
        self.buf = self.buf[len(data):]
        return out


# eSTREAM Salsa20/20, 256-bit key, set 1, vector 0.
assert _salsa_block(b"\x80" + b"\x00" * 31, b"\x00" * 8, 0).hex().upper() == (
    "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844"
    "B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117")


class ChaCha20Stream:
    """IETF ChaCha20 (96-bit nonce, 32-bit counter from 0) as one stream."""

    def __init__(self, key, nonce12):
        self.enc = Cipher(algorithms.ChaCha20(key, b"\x00" * 4 + nonce12), None).encryptor()

    def xor(self, data):
        return self.enc.update(data)


# ---------------------------------------------------------------- helpers


def b64(b):
    return base64.b64encode(b).decode()


def sha256(b):
    return hashlib.sha256(b).digest()


def aes_cbc(key, iv, data):
    p = padding.PKCS7(128).padder()
    data = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def aes_kdf(key, seed, rounds):
    e = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()
    for _ in range(rounds):
        key = e.update(key)
    return sha256(key)


def argon2d_cli(password, salt, t, m_kib, p, version=0x13):
    out = subprocess.run(
        ["argon2", salt.decode(), "-d", "-t", str(t), "-k", str(m_kib), "-p", str(p), "-l", "32", "-r",
         "-v", "13" if version == 0x13 else "10"],
        input=password, capture_output=True, check=True)
    return bytes.fromhex(out.stdout.decode().strip())


def composite(password=None, keyfile_key=None):
    parts = b""
    if password is not None:
        parts += sha256(password)
    if keyfile_key is not None:
        parts += keyfile_key
    return sha256(parts)


def protect(stream, value):
    """A protected value: base64 of the value XORed with the inner stream."""
    return b64(stream.xor(value.encode()))


def xml_escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def s(stream, key, value, protected=False):
    if protected:
        return f'<String><Key>{xml_escape(key)}</Key><Value Protected="True">{protect(stream, value)}</Value></String>'
    return f"<String><Key>{xml_escape(key)}</Key><Value>{xml_escape(value)}</Value></String>"


def uuid_b64(name):
    return b64(uuid.uuid5(uuid.NAMESPACE_URL, "svimport-fixture:" + name).bytes)


# ---------------------------------------------------------------- KDBX 3.1


def kdbx31():
    """KDBX 3.1: AES-256-CBC, AES-KDF, gzip, Salsa20, hashed blocks; password."""
    master_seed, iv = os.urandom(32), os.urandom(16)
    transform_seed, rounds = os.urandom(32), 6000
    stream_key, stream_start = os.urandom(32), os.urandom(32)

    def field(fid, data):
        return struct.pack("<BH", fid, len(data)) + data

    header = struct.pack("<III", 0x9AA2D903, 0xB54BFB67, 0x00030001)
    header += field(2, bytes.fromhex("31c1f2e6bf714350be5805216afc5aff"))
    header += field(3, struct.pack("<I", 1))
    header += field(4, master_seed)
    header += field(5, transform_seed)
    header += field(6, struct.pack("<Q", rounds))
    header += field(7, iv)
    header += field(8, stream_key)
    header += field(9, stream_start)
    header += field(10, struct.pack("<I", 2))
    header += field(0, b"\r\n\r\n")

    st = Salsa20Stream(sha256(stream_key), bytes.fromhex("E830094B97205D2A"))
    t = "2025-01-02T03:04:05Z"
    times = f"<Times><CreationTime>{t}</CreationTime><LastModificationTime>{t}</LastModificationTime></Times>"
    # Protected values consume the stream in document order, so the XML
    # is written front to back, calling s(..., protected=True) in order.
    x = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<KeePassFile><Meta>'
    x += "<Generator>make_fixtures.py</Generator>"
    x += f"<HeaderHash>{b64(sha256(header))}</HeaderHash>"
    x += "<DatabaseName>Fixture 3.1</DatabaseName>"
    x += "<RecycleBinEnabled>True</RecycleBinEnabled>"
    x += f"<RecycleBinUUID>{uuid_b64('recycle')}</RecycleBinUUID>"
    x += f'<Binaries><Binary ID="0" Compressed="False" Protected="True">{protect(st, "-----BEGIN KEY-----")}</Binary></Binaries>'
    x += "</Meta><Root>"
    x += f"<Group><UUID>{uuid_b64('root')}</UUID><Name>Passwords</Name>{times}"
    x += f"<Entry><UUID>{uuid_b64('bank')}</UUID><Tags>finance;important</Tags>{times}"
    x += s(st, "Notes", "PIN is in the safe\nsecond line")
    x += s(st, "Password", "b4nk-p4ss & <more>", True)
    x += s(st, "Recovery code", "RC-123-456", True)
    x += s(st, "Security question", "first pet")
    x += s(st, "Title", "Bank")
    x += s(st, "URL", "https://bank.example/login")
    x += s(st, "UserName", "ada")
    x += "<AutoType><Enabled>True</Enabled></AutoType>"
    x += f"<History><Entry><UUID>{uuid_b64('bank')}</UUID>{times}"
    x += s(st, "Password", "old-bank-pass", True)
    x += s(st, "Title", "Bank")
    x += "</Entry></History></Entry>"
    x += f"<Entry><UUID>{uuid_b64('wifi')}</UUID>{times}"
    x += s(st, "Notes", "SSID home, WPA3")
    x += s(st, "Password", "", True)
    x += s(st, "Title", "Wifi note")
    x += s(st, "URL", "")
    x += s(st, "UserName", "")
    x += "</Entry>"
    x += f"<Group><UUID>{uuid_b64('work')}</UUID><Name>Work</Name>{times}"
    x += f"<Entry><UUID>{uuid_b64('vpn')}</UUID>{times}"
    x += s(st, "otp", "otpauth://totp/VPN:a.lovelace?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=VPN", True)
    x += s(st, "Password", "vpn-secret", True)
    x += s(st, "Title", "VPN")
    x += s(st, "UserName", "a.lovelace")
    x += "</Entry>"
    x += f"<Group><UUID>{uuid_b64('servers')}</UUID><Name>Servers</Name>{times}"
    x += f"<Entry><UUID>{uuid_b64('db1')}</UUID>{times}"
    x += s(st, "Password", "r00t", True)
    x += s(st, "Title", "db1")
    x += s(st, "TOTP Seed", "GEZDGNBVGY3TQOJQ", True)
    x += s(st, "TOTP Settings", "60;8")
    x += s(st, "UserName", "root")
    x += '<Binary><Key>id_ed25519</Key><Value Ref="0"/></Binary>'
    x += "</Entry></Group></Group>"
    x += f"<Group><UUID>{uuid_b64('recycle')}</UUID><Name>Recycle Bin</Name>{times}"
    x += f"<Entry><UUID>{uuid_b64('gone')}</UUID>{times}"
    x += s(st, "Password", "deleted-pass", True)
    x += s(st, "Title", "Deleted thing")
    x += "</Entry></Group>"
    x += f"<Entry><UUID>{uuid_b64('steam')}</UUID>{times}"
    x += s(st, "Password", "steam-pass", True)
    x += s(st, "Title", "Steam")
    x += s(st, "TOTP Seed", "STEAMSTEAMSTEAM2", True)
    x += s(st, "TOTP Settings", "30;S")
    x += s(st, "UserName", "gaben")
    x += "</Entry>"
    x += "</Group><DeletedObjects/></Root></KeePassFile>"

    body = gzip.compress(x.encode())
    blocks = b""
    for i, off in enumerate(range(0, len(body), 1000)):  # small blocks, to test several
        chunk = body[off:off + 1000]
        blocks += struct.pack("<I", i) + sha256(chunk) + struct.pack("<I", len(chunk)) + chunk
    n = (len(body) + 999) // 1000
    blocks += struct.pack("<I", n) + b"\x00" * 32 + struct.pack("<I", 0)

    transformed = aes_kdf(composite(PASSWORD), transform_seed, rounds)
    key = sha256(master_seed + transformed)
    return header + aes_cbc(key, iv, stream_start + blocks)


# ---------------------------------------------------------------- KDBX 4


def variant_dict(entries):
    out = struct.pack("<H", 0x0100)
    for typ, k, v in entries:
        out += struct.pack("<BI", typ, len(k)) + k + struct.pack("<I", len(v)) + v
    return out + b"\x00"


def kdbx4_time(y):
    # seconds since 0001-01-01, little-endian, base64
    import datetime
    d = datetime.datetime(y, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    secs = int((d - datetime.datetime(1, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds())
    return b64(struct.pack("<q", secs))


def kdbx4(*, cipher, kdf, key, minor, compress, entries_xml, attachments=()):
    master_seed = os.urandom(32)
    iv = os.urandom(12 if cipher == "chacha20" else 16)
    cipher_uuid = {"aes": "31c1f2e6bf714350be5805216afc5aff", "chacha20": "d6038a2b8b6f4cb5a524339a31dbb59a"}[cipher]

    def field(fid, data):
        return struct.pack("<BI", fid, len(data)) + data

    header = struct.pack("<III", 0x9AA2D903, 0xB54BFB67, 0x00040000 | minor)
    header += field(2, bytes.fromhex(cipher_uuid))
    header += field(3, struct.pack("<I", 1 if compress else 0))
    header += field(4, master_seed)
    header += field(7, iv)
    header += field(11, kdf["dict"])
    header += field(0, b"\r\n\r\n")

    transformed = kdf["derive"](key)
    enc_key = sha256(master_seed + transformed)
    hmac_key = hashlib.sha512(master_seed + transformed + b"\x01").digest()

    def block_key(i):
        return hashlib.sha512(struct.pack("<Q", i) + hmac_key).digest()

    inner_key = os.urandom(64)
    h = hashlib.sha512(inner_key).digest()
    st = ChaCha20Stream(h[:32], h[32:44])
    xml = entries_xml(st).encode()

    inner = struct.pack("<BI", 1, 4) + struct.pack("<I", 3)
    inner += struct.pack("<BI", 2, len(inner_key)) + inner_key
    for flags, data in attachments:
        inner += struct.pack("<BI", 3, 1 + len(data)) + bytes([flags]) + data
    inner += struct.pack("<BI", 0, 0)
    plain = inner + xml
    if compress:
        plain = gzip.compress(plain)
    if cipher == "chacha20":
        ct = ChaCha20Stream(enc_key, iv).xor(plain)
    else:
        ct = aes_cbc(enc_key, iv, plain)

    out = header + sha256(header) + hmac.new(block_key(0xFFFFFFFFFFFFFFFF), header, hashlib.sha256).digest()
    i = 0
    for off in range(0, len(ct), 700):  # small blocks, to test several
        chunk = ct[off:off + 700]
        mac = hmac.new(block_key(i), struct.pack("<QI", i, len(chunk)) + chunk, hashlib.sha256).digest()
        out += mac + struct.pack("<I", len(chunk)) + chunk
        i += 1
    out += hmac.new(block_key(i), struct.pack("<QI", i, 0), hashlib.sha256).digest() + struct.pack("<I", 0)
    return out


def kdbx4_argon2d():
    """KDBX 4.0: ChaCha20, Argon2d, gzip; password and an XML v2.0 key file."""
    salt = b"fixture-salt-for-kdbx4-argon2d!!"  # printable: the argon2 tool takes the salt as an argument
    t, m_kib, p = 2, 1024, 2
    kdf = {
        "dict": variant_dict([
            (0x42, b"$UUID", bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")),
            (0x42, b"S", salt), (0x04, b"P", struct.pack("<I", p)), (0x05, b"M", struct.pack("<Q", m_kib * 1024)),
            (0x05, b"I", struct.pack("<Q", t)), (0x04, b"V", struct.pack("<I", 0x13)),
        ]),
        "derive": lambda k: argon2d_cli(k, salt, t, m_kib, p),
    }
    keyfile_key = bytes.fromhex("0123456789abcdef" * 4)
    keyfile = (
        '<?xml version="1.0" encoding="utf-8"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n'
        f'\t<Key>\n\t\t<Data Hash="{sha256(keyfile_key)[:4].hex().upper()}">\n'
        "\t\t\t01234567 89ABCDEF 01234567 89ABCDEF\n\t\t\t01234567 89ABCDEF 01234567 89ABCDEF\n"
        "\t\t</Data>\n\t</Key>\n</KeyFile>\n")
    tm = kdbx4_time(2025)
    times = f"<Times><CreationTime>{tm}</CreationTime><LastModificationTime>{tm}</LastModificationTime></Times>"

    def xml(st):
        x = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<KeePassFile><Meta>'
        x += "<Generator>make_fixtures.py</Generator><RecycleBinEnabled>False</RecycleBinEnabled>"
        x += "<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID></Meta><Root>"
        x += f"<Group><UUID>{uuid_b64('r4')}</UUID><Name>Root</Name>{times}"
        x += f"<Group><UUID>{uuid_b64('mail')}</UUID><Name>Mail &amp; Chat</Name>{times}"
        x += f"<Entry><UUID>{uuid_b64('mailbox')}</UUID><Tags>mail,personal</Tags>{times}"
        x += s(st, "Title", "Mailbox")
        x += s(st, "UserName", "ada@example.org")
        x += s(st, "Password", "m4il-p4ss", True)
        x += s(st, "URL", "https://mail.example.org")
        x += s(st, "KP2A_URL", "https://webmail.example.org")
        x += s(st, "TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP", True)
        x += s(st, "TimeOtp-Length", "8")
        x += s(st, "TimeOtp-Algorithm", "HMAC-SHA-256")
        x += s(st, "PIN", "4321", True)
        x += '<Binary><Key>backup-codes.txt</Key><Value Ref="0"/></Binary>'
        x += "</Entry></Group>"
        x += f"<Entry><UUID>{uuid_b64('passkey')}</UUID>{times}"
        x += s(st, "Title", "Passkey site")
        x += s(st, "UserName", "ada")
        x += s(st, "KPEX_PASSKEY_USERNAME", "ada")
        x += s(st, "KPEX_PASSKEY_PRIVATE_KEY_PEM", "-----BEGIN PRIVATE KEY-----\nMC4CAQ...\n-----END PRIVATE KEY-----", True)
        x += s(st, "KPEX_PASSKEY_RELYING_PARTY", "passkey.example")
        x += "</Entry>"
        x += "</Group></Root></KeePassFile>"
        return x

    data = kdbx4(cipher="chacha20", kdf=kdf, key=composite(PASSWORD, keyfile_key), minor=0, compress=True,
                 entries_xml=xml, attachments=[(1, b"code-1 code-2 code-3")])
    return data, keyfile.encode()


def kdbx41_argon2id_keyfile():
    """KDBX 4.1: AES-256-CBC, Argon2id, no gzip; a key file alone (64 hex digits)."""
    salt = os.urandom(32)
    t, m_kib, p = 2, 512, 1
    kdf = {
        "dict": variant_dict([
            (0x42, b"$UUID", bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")),
            (0x42, b"S", salt), (0x04, b"P", struct.pack("<I", p)), (0x05, b"M", struct.pack("<Q", m_kib * 1024)),
            (0x05, b"I", struct.pack("<Q", t)), (0x04, b"V", struct.pack("<I", 0x13)),
        ]),
        "derive": lambda k: Argon2id(salt=salt, length=32, iterations=t, lanes=p, memory_cost=m_kib).derive(k),
    }
    keyfile = os.urandom(32).hex().encode()  # 64 hex digits: the key in hex
    tm = kdbx4_time(2026)
    times = f"<Times><CreationTime>{tm}</CreationTime></Times>"

    def xml(st):
        x = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<KeePassFile><Meta>'
        x += "<Generator>make_fixtures.py</Generator></Meta><Root>"
        x += f"<Group><UUID>{uuid_b64('r41')}</UUID><Name>Database</Name>{times}"
        x += f"<Entry><UUID>{uuid_b64('api')}</UUID>{times}"
        x += s(st, "Title", "API token")
        x += s(st, "Password", "tok_live_0123456789", True)
        x += s(st, "Notes", "rotate yearly")
        x += "</Entry></Group></Root></KeePassFile>"
        return x

    data = kdbx4(cipher="aes", kdf=kdf, key=composite(None, bytes.fromhex(keyfile.decode())), minor=1,
                 compress=False, entries_xml=xml)
    return data, keyfile


# ---------------------------------------------------------------- Bitwarden

BITWARDEN_INNER = {
    "encrypted": False,
    "folders": [{"id": "f1", "name": "Work/Servers"}],
    "items": [
        {"id": "i1", "folderId": "f1", "type": 1, "name": "db.example", "notes": None, "favorite": False,
         "fields": [{"name": "port", "value": "5432", "type": 0, "linkedId": None},
                    {"name": "root pw", "value": "hunter22", "type": 1, "linkedId": None}],
         "login": {"uris": [{"match": None, "uri": "https://db.example"}], "username": "dba",
                   "password": "pg-secret", "totp": "JBSWY3DPEHPK3PXP"},
         "collectionIds": None},
        {"id": "i2", "folderId": None, "type": 3, "name": "Visa", "notes": "backup card",
         "card": {"cardholderName": "Ada Lovelace", "brand": "Visa", "number": "4111111111111111",
                  "expMonth": "7", "expYear": "2031", "code": "123"}},
    ],
}


def bitwarden_encrypted(kdf_type):
    salt = b64(os.urandom(16))
    if kdf_type == 0:
        iters = 5000
        key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt.encode(), iterations=iters).derive(PASSWORD)
        extra = {}
    else:
        iters, mem, par = 3, 16, 4
        key = Argon2id(salt=sha256(salt.encode()), length=32, iterations=iters, lanes=par,
                       memory_cost=mem * 1024).derive(PASSWORD)
        extra = {"kdfMemory": mem, "kdfParallelism": par}
    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(key)
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(key)

    def enc_string(plain):
        iv = os.urandom(16)
        ct = aes_cbc(enc_key, iv, plain.encode())
        mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
        return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"

    doc = {"encrypted": True, "passwordProtected": True, "salt": salt, "kdfType": kdf_type,
           "kdfIterations": iters, **extra,
           "encKeyValidation_DO_NOT_EDIT": enc_string(str(uuid.uuid4())),
           "data": enc_string(json.dumps(BITWARDEN_INNER))}
    return json.dumps(doc, indent=2).encode()


# ---------------------------------------------------------------- Aegis

AEGIS_DB = {
    "version": 3,
    "entries": [
        {"type": "totp", "uuid": "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d", "name": "ada@example.org",
         "issuer": "GitHub", "note": "work account", "favorite": False, "icon": None,
         "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA256", "digits": 8, "period": 60},
         "groups": ["a1b2c3d4-0000-4000-8000-000000000001"]},
        {"type": "hotp", "uuid": "9f1c7c1e-7d7e-4f4e-9d3a-3f2f5d2b8e11", "name": "ada", "issuer": "Bank",
         "note": "", "favorite": True, "icon": None,
         "info": {"secret": "GEZDGNBVGY3TQOJQ", "algo": "SHA1", "digits": 6, "counter": 7}, "groups": []},
        {"type": "steam", "uuid": "4c2e1b7a-1c1a-4b9e-8b4c-2e1f0f9d8c7b", "name": "gaben", "issuer": "Steam",
         "note": "", "favorite": False, "icon": None,
         "info": {"secret": "STEAMSTEAMSTEAM2", "algo": "SHA1", "digits": 5, "period": 30}, "groups": []},
        {"type": "motp", "uuid": "0b8f0a3c-5d1e-4c7b-9a2f-6e5d4c3b2a19", "name": "legacy", "issuer": "Old VPN",
         "note": "", "favorite": False, "icon": None,
         "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "MD5", "digits": 6, "period": 10, "pin": "1234"},
         "groups": []},
    ],
    "groups": [{"uuid": "a1b2c3d4-0000-4000-8000-000000000001", "name": "Work"}],
}


def aegis_encrypted():
    master = AESGCM.generate_key(bit_length=256)
    salt, n, r, p = os.urandom(32), 1 << 10, 8, 1
    kek = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(PASSWORD)
    nonce = os.urandom(12)
    sealed = AESGCM(kek).encrypt(nonce, master, None)
    db_nonce = os.urandom(12)
    db = AESGCM(master).encrypt(db_nonce, json.dumps(AEGIS_DB).encode(), None)
    doc = {
        "version": 1,
        "header": {
            "slots": [
                {"type": 2, "uuid": str(uuid.uuid4()), "key": os.urandom(32).hex(),
                 "key_params": {"nonce": os.urandom(12).hex(), "tag": os.urandom(16).hex()}},
                {"type": 1, "uuid": str(uuid.uuid4()), "key": sealed[:-16].hex(),
                 "key_params": {"nonce": nonce.hex(), "tag": sealed[-16:].hex()},
                 "n": n, "r": r, "p": p, "salt": salt.hex(), "repaired": True, "is_backup": False},
            ],
            "params": {"nonce": db_nonce.hex(), "tag": db[-16:].hex()},
        },
        "db": b64(db[:-16]),
    }
    return json.dumps(doc, indent=4).encode()


def main():
    def write(name, data):
        with open(name, "wb") as f:
            f.write(data)
        print("wrote", name, len(data), "bytes")

    write("kdbx31-aes-aeskdf-salsa20.kdbx", kdbx31())
    data, keyfile = kdbx4_argon2d()
    write("kdbx4-chacha20-argon2d.kdbx", data)
    write("kdbx4-chacha20-argon2d.keyx", keyfile)
    data, keyfile = kdbx41_argon2id_keyfile()
    write("kdbx41-aes-argon2id.kdbx", data)
    write("kdbx41-aes-argon2id.key", keyfile)
    write("bitwarden-encrypted-pbkdf2.json", bitwarden_encrypted(0))
    write("bitwarden-encrypted-argon2id.json", bitwarden_encrypted(1))
    write("aegis-encrypted.json", aegis_encrypted())


if __name__ == "__main__":
    main()
