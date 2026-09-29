package svcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"
)

// rfc9106Input is the input of every test vector in RFC 9106 section 5.
func rfc9106Input() Argon2Input {
	return Argon2Input{
		Password:  bytes.Repeat([]byte{1}, 32),
		Salt:      bytes.Repeat([]byte{2}, 16),
		Secret:    bytes.Repeat([]byte{3}, 8),
		Data:      bytes.Repeat([]byte{4}, 12),
		Time:      3,
		MemoryKiB: 32,
		Threads:   4,
		KeyLen:    32,
	}
}

func TestArgon2MatchesTheRFC9106TestVectors(t *testing.T) {
	for variant, want := range map[string]string{
		Argon2d:  "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb", // section 5.1
		Argon2i:  "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8", // section 5.2
		Argon2id: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", // section 5.3
	} {
		got, err := Argon2(variant, rfc9106Input())
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != want {
			t.Errorf("%s:\n got %x\nwant %s", variant, got, want)
		}
	}
}

func TestArgon2dMatchesTheReferenceImplementation(t *testing.T) {
	// Expected outputs from the reference implementation (phc-winner-argon2):
	//   echo -n password | argon2 somesaltsomesalt -d -t 2 -k 256 -p 4 -l 32 -r
	//   echo -n password | argon2 somesaltsomesalt -d -t 3 -k 1024 -p 3 -l 64 -r
	//   echo -n password | argon2 somesaltsomesalt -d -t 1 -k 64 -p 1 -l 32 -v 10 -r
	for _, c := range []struct {
		time, mem, threads, keyLen, version uint32
		want                                string
	}{
		{2, 256, 4, 32, 0x13, "9ad5efe37284485d54051c2455e9d516ffd8aca3a3c73584b630afafbff3c6b1"},
		{3, 1024, 3, 64, 0x13, "5a7c29c9eafdc8643e01871e3c2b2162664aa0eb4c1b3afd58d2f4d56f9928ca05c4b3f0ea878ad552ba31621129f02a8a26f5157ec2908df690c02b916799cd"},
		{1, 64, 1, 32, 0x10, "e69987878104852e1141807e2c9c4c597f23d221a5959f515b4c1a0750ae2aee"},
	} {
		got, err := Argon2(Argon2d, Argon2Input{Password: []byte("password"), Salt: []byte("somesaltsomesalt"),
			Time: c.time, MemoryKiB: c.mem, Threads: c.threads, KeyLen: c.keyLen, Version: c.version})
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("t=%d m=%d p=%d v=0x%x:\n got %x\nwant %s", c.time, c.mem, c.threads, c.version, got, c.want)
		}
	}
}

func TestArgon2AgreesWithXCrypto(t *testing.T) {
	pass, salt := []byte("correct horse"), []byte("0123456789abcdef")
	for _, c := range []struct{ time, mem, threads, keyLen uint32 }{
		{1, 64, 1, 32}, {2, 300, 3, 16}, {3, 1024, 4, 100},
	} {
		in := Argon2Input{Password: pass, Salt: salt, Time: c.time, MemoryKiB: c.mem, Threads: c.threads, KeyLen: c.keyLen}
		id, _ := Argon2(Argon2id, in)
		if want := argon2.IDKey(pass, salt, c.time, c.mem, uint8(c.threads), c.keyLen); !bytes.Equal(id, want) {
			t.Errorf("argon2id %+v differs from x/crypto", c)
		}
		i, _ := Argon2(Argon2i, in)
		if want := argon2.Key(pass, salt, c.time, c.mem, uint8(c.threads), c.keyLen); !bytes.Equal(i, want) {
			t.Errorf("argon2i %+v differs from x/crypto", c)
		}
	}
}

func TestArgon2RefusesBadParameters(t *testing.T) {
	good := Argon2Input{Password: []byte("p"), Salt: make([]byte, 16), Time: 1, MemoryKiB: 64, Threads: 1, KeyLen: 32}
	for name, mutate := range map[string]func(*Argon2Input){
		"no passes":      func(in *Argon2Input) { in.Time = 0 },
		"no lanes":       func(in *Argon2Input) { in.Threads = 0 },
		"too little ram": func(in *Argon2Input) { in.MemoryKiB = 4 },
		"too much ram":   func(in *Argon2Input) { in.MemoryKiB = 1 << 31 },
		"short salt":     func(in *Argon2Input) { in.Salt = in.Salt[:4] },
		"short key":      func(in *Argon2Input) { in.KeyLen = 2 },
		"odd version":    func(in *Argon2Input) { in.Version = 0x12 },
	} {
		in := good
		mutate(&in)
		if _, err := Argon2(Argon2d, in); !errors.Is(err, ErrArgon2) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Argon2("argon3", good); !errors.Is(err, ErrArgon2) {
		t.Errorf("an unknown variant: %v", err)
	}
}
