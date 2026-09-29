# svage test data

## cctv/

The age test vectors of the Community Cryptography Test Vectors project
(C2SP CCTV), copied unchanged from
<https://github.com/C2SP/CCTV/tree/main/age/testdata> at commit
`50a8ecf2a220f4c8bdc4f085789b8e85c26829e7` (25 September 2026).

Each file is one vector: a few `key: value` lines (`expect`, `payload`,
`identity`, `passphrase`, `armored`, `compressed`, `file key`, `comment`),
an empty line, then an age file, zlib-compressed when `compressed: zlib`
says so. The format is described in the upstream
[README](https://github.com/C2SP/CCTV/blob/main/age/README.md);
`testkit_test.go` runs every one of them.

**Licence.** Upstream offers the vectors under the Zero-Clause BSD licence,
CC0 1.0, or the Unlicense, at the user's choice; copying them needs no
attribution. This copy takes them under CC0 1.0
(<https://creativecommons.org/publicdomain/zero/1.0/>). Copyright (c) 2022
The age Authors.

To update: replace the files in `cctv/` with the upstream `age/testdata`
folder, update the commit above, and run `go test ./svage/`.

## interop/

Files written by the reference implementation (filippo.io/age v1.3.2) for
recipient types the CCTV vectors do not cover: SSH keys (the ed25519 key is
the one in age's own test scripts; the RSA key was made for this), and the
hardware-tag recipients. They were generated once, outside this repository,
by `interop/generate.go.txt` in the module `interop/generate.go.mod.txt`
describes; secretvault's build does not depend on that code. Its `check`
mode also encrypts with each implementation and decrypts with the other,
for every recipient type.

## spec-keys.txt

The example keys quoted in the age specification, which
`TestSpecExampleKeysPairUp` checks pair up as the spec says.
