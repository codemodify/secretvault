package svage

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

// The parsers see hostile input first, so they are fuzzed, seeded with
// every CCTV vector: go test -fuzz=FuzzHeader ./svage/

func addVectorSeeds(f *testing.F, armored bool) {
	f.Helper()
	for _, v := range loadVectors(f) {
		if v.armored == armored {
			f.Add(v.file)
		}
	}
}

// A header either fails to parse, or is exactly what marshalling its
// stanzas and MAC gives back: there is one encoding of each header.
func FuzzHeader(f *testing.F) {
	addVectorSeeds(f, false)
	f.Add([]byte("age-encryption.org/v1\n-> a\n\n--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		hdr, err := parseHeader(bufio.NewReader(bytes.NewReader(b)))
		if err != nil {
			return
		}
		if hdr.size > int64(len(b)) || len(hdr.stanzas) == 0 || len(hdr.stanzas) > MaxStanzas {
			t.Fatalf("impossible header: size %d of %d, %d stanzas", hdr.size, len(b), len(hdr.stanzas))
		}
		again, err := marshalHeader(hdr.stanzas, func(macked []byte) []byte {
			if !bytes.Equal(macked, hdr.macked) {
				t.Fatal("the MAC covers different bytes")
			}
			return hdr.mac
		})
		if err != nil {
			t.Fatalf("a parsed header does not marshal: %v", err)
		}
		if !bytes.Equal(again, b[:hdr.size]) {
			t.Fatalf("a header re-encodes differently:\n%q\n%q", again, b[:hdr.size])
		}
	})
}

// Armor either fails, or decodes to bytes that re-armor to the input
// (give or take CRLF and the whitespace around it).
func FuzzArmor(f *testing.F) {
	addVectorSeeds(f, true)
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := io.ReadAll(NewArmorReader(bytes.NewReader(b)))
		if err != nil {
			return
		}
		var again bytes.Buffer
		w := NewArmorWriter(&again)
		w.Write(out)
		w.Close()
		want := append(bytes.TrimSpace(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))), '\n')
		if !bytes.Equal(again.Bytes(), want) {
			t.Fatalf("armor re-encodes differently:\n%q\n%q", again.Bytes(), want)
		}
	})
}

// Decrypting anything never panics, and never returns plaintext from a
// file that does not authenticate to the end.
func FuzzDecrypt(f *testing.F) {
	addVectorSeeds(f, false)
	id, _ := ParseX25519Identity("AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0")
	pass, _ := NewScryptIdentity([]byte("password"))
	pass.SetMaxWorkFactor(12)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Decrypt(bytes.NewReader(b), id, pass)
		if err != nil {
			return
		}
		io.Copy(io.Discard, r)
		if ra, size, err := DecryptReaderAt(bytes.NewReader(b), int64(len(b)), id, pass); err == nil {
			io.Copy(io.Discard, io.NewSectionReader(ra, 0, size))
		}
	})
}
