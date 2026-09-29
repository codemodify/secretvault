package svimport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svotp"
)

// Aegis Authenticator's vault (https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md):
// {"version": 1, "header": {...}, "db": ...}. A plain vault has a null
// header and db as an object; an encrypted one has password slots, each
// holding the master key sealed with AES-256-GCM under a key scrypt
// derives from the password, and db as base64 AES-256-GCM ciphertext under
// the master key. Entries (totp, hotp, steam) become "otp" items; groups
// become folders. Aegis's MOTP and Yandex keys have no otpauth form and
// are left behind with a warning.

type aegisFile struct {
	Header struct {
		Slots []struct {
			Type      int    `json:"type"`
			Key       string `json:"key"`
			KeyParams struct {
				Nonce string `json:"nonce"`
				Tag   string `json:"tag"`
			} `json:"key_params"`
			N    int    `json:"n"`
			R    int    `json:"r"`
			P    int    `json:"p"`
			Salt string `json:"salt"`
		} `json:"slots"`
		Params *struct {
			Nonce string `json:"nonce"`
			Tag   string `json:"tag"`
		} `json:"params"`
	} `json:"header"`
	DB json.RawMessage `json:"db"`
}

type aegisDB struct {
	Version int `json:"version"`
	Entries []struct {
		Type   string   `json:"type"`
		Name   string   `json:"name"`
		Issuer string   `json:"issuer"`
		Note   string   `json:"note"`
		Group  string   `json:"group"`  // content version 2
		Groups []string `json:"groups"` // content version 3: group uuids
		Info   struct {
			Secret  string `json:"secret"`
			Algo    string `json:"algo"`
			Digits  int    `json:"digits"`
			Period  int    `json:"period"`
			Counter uint64 `json:"counter"`
		} `json:"info"`
	} `json:"entries"`
	Groups []struct {
		UUID string `json:"uuid"`
		Name string `json:"name"`
	} `json:"groups"`
}

func readAegis(b *builder, data []byte, opts Options) error {
	var f aegisFile
	if err := json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &f); err != nil {
		return jsonError("the Aegis vault", err)
	}
	raw := []byte(f.DB)
	if len(raw) > 0 && raw[0] == '"' {
		var err error
		if raw, err = aegisDecrypt(&f, opts.Passphrase); err != nil {
			return err
		}
		defer clear(raw)
	}
	var db aegisDB
	if err := json.Unmarshal(raw, &db); err != nil {
		return jsonError("the Aegis vault's contents", err)
	}
	groups := map[string]string{}
	for _, g := range db.Groups {
		groups[g.UUID] = g.Name
	}
	for _, e := range db.Entries {
		d := &draft{kind: kOTP, title: otpTitle(e.Issuer, e.Name)}
		switch {
		case len(e.Groups) > 0:
			d.folder = []string{groups[e.Groups[0]]}
		case e.Group != "":
			d.folder = []string{e.Group}
		}
		k := &svotp.Key{Issuer: e.Issuer, Account: e.Name, Algorithm: hashName(e.Info.Algo),
			Digits: e.Info.Digits, Period: e.Info.Period, Counter: e.Info.Counter}
		switch strings.ToLower(e.Type) {
		case "totp":
			k.Type = "totp"
		case "hotp":
			k.Type = "hotp"
		case "steam":
			k.Type, k.Steam, k.Digits = "totp", true, 5
		default:
			b.warn("%s: not imported: Aegis %s keys have no otpauth form", d.title, strings.ToUpper(e.Type))
			continue
		}
		var uri string
		secret, err := svotp.DecodeSecret(e.Info.Secret)
		if err == nil {
			k.Secret = secret
			uri, err = otpKeyURI(k)
		}
		k.Wipe()
		if err != nil {
			b.warn("%s: not imported: its key could not be read", d.title)
			continue
		}
		d.set(fOTP, svcore.FieldOTP, uri)
		d.notes(e.Note)
		b.add(d)
	}
	return nil
}

// aegisDecrypt opens an encrypted vault's db with the password.
func aegisDecrypt(f *aegisFile, password []byte) ([]byte, error) {
	var db string
	if err := json.Unmarshal(f.DB, &db); err != nil {
		return nil, fmt.Errorf("%w: Aegis db", ErrFormat)
	}
	ct, err := base64.StdEncoding.DecodeString(db)
	if err != nil {
		return nil, fmt.Errorf("%w: Aegis db is not base64", ErrFormat)
	}
	if f.Header.Params == nil {
		return nil, fmt.Errorf("%w: encrypted Aegis vault without parameters", ErrFormat)
	}
	if len(password) == 0 {
		return nil, ErrPassphrase
	}
	tried := false
	for _, s := range f.Header.Slots {
		if s.Type != 1 {
			continue // raw and biometric slots need keys that stay on the phone
		}
		if s.N < 2 || s.N > 1<<22 || s.R < 1 || s.R > 32 || s.P < 1 || s.P > 16 {
			return nil, fmt.Errorf("%w: scrypt N=%d r=%d p=%d", ErrUnsupported, s.N, s.R, s.P)
		}
		salt, err1 := hex.DecodeString(s.Salt)
		sealed, err2 := hex.DecodeString(s.Key)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%w: an Aegis slot is not hex", ErrFormat)
		}
		tried = true
		kek, err := scrypt.Key(password, salt, s.N, s.R, s.P, 32)
		if err != nil {
			return nil, err
		}
		master, err := gcmOpen(kek, s.KeyParams.Nonce, sealed, s.KeyParams.Tag)
		clear(kek)
		if err != nil {
			continue
		}
		defer clear(master)
		plain, err := gcmOpen(master, f.Header.Params.Nonce, ct, f.Header.Params.Tag)
		if err != nil {
			return nil, fmt.Errorf("%w: the Aegis vault's contents do not authenticate", ErrFormat)
		}
		return plain, nil
	}
	if !tried {
		return nil, fmt.Errorf("%w: this Aegis vault has no password slot", ErrUnsupported)
	}
	return nil, ErrWrongKey
}

// gcmOpen decrypts AES-256-GCM, with the nonce and tag in hex as Aegis
// writes them.
func gcmOpen(key []byte, nonceHex string, ct []byte, tagHex string) ([]byte, error) {
	nonce, err1 := hex.DecodeString(nonceHex)
	tag, err2 := hex.DecodeString(tagHex)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("%w: Aegis parameters are not hex", ErrFormat)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(blk, len(nonce))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return aead.Open(nil, nonce, append(append([]byte(nil), ct...), tag...), nil)
}
