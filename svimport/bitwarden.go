package svimport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/codemodify/secretvault/svcore"
)

// Bitwarden's JSON export, as the web vault, the apps and the bw CLI write
// it: {"encrypted": false, "folders": [...], "items": [...]}, or an
// organisation's with "collections" in place of folders. A
// password-protected export wraps that JSON as one encrypted string, keyed
// from the password with PBKDF2-SHA256 or Argon2id, then stretched with
// HKDF into an AES-256-CBC key and an HMAC-SHA256 key (Bitwarden's
// "type 2" cipher strings: "2.iv|ciphertext|mac", base64). An export
// restricted to the account ("encrypted": true without a password) can
// only be read by Bitwarden itself.

type bwExport struct {
	Encrypted         bool   `json:"encrypted"`
	PasswordProtected bool   `json:"passwordProtected"`
	Salt              string `json:"salt"`
	KdfType           int    `json:"kdfType"`
	KdfIterations     int    `json:"kdfIterations"`
	KdfMemory         int    `json:"kdfMemory"`
	KdfParallelism    int    `json:"kdfParallelism"`
	EncKeyValidation  string `json:"encKeyValidation_DO_NOT_EDIT"`
	Data              string `json:"data"`

	Folders     []bwFolder `json:"folders"`
	Collections []bwFolder `json:"collections"`
	Items       []bwItem   `json:"items"`
}

type bwFolder struct {
	ID   jstr `json:"id"`
	Name jstr `json:"name"`
}

type bwItem struct {
	FolderID        jstr              `json:"folderId"`
	CollectionIDs   []jstr            `json:"collectionIds"`
	Type            int               `json:"type"`
	Name            jstr              `json:"name"`
	Notes           jstr              `json:"notes"`
	Fields          []bwField         `json:"fields"`
	Login           *bwLogin          `json:"login"`
	Card            *bwCard           `json:"card"`
	Identity        *bwIdentity       `json:"identity"`
	SSHKey          *bwSSHKey         `json:"sshKey"`
	PasswordHistory []json.RawMessage `json:"passwordHistory"`
	DeletedDate     jstr              `json:"deletedDate"`
	Attachments     []json.RawMessage `json:"attachments"`
}

type bwField struct {
	Name  jstr `json:"name"`
	Value jstr `json:"value"`
	Type  int  `json:"type"` // 0 text, 1 hidden, 2 boolean, 3 linked
}

type bwLogin struct {
	URIs             []struct{ URI jstr } `json:"uris"`
	Username         jstr                 `json:"username"`
	Password         jstr                 `json:"password"`
	TOTP             jstr                 `json:"totp"`
	Fido2Credentials []json.RawMessage    `json:"fido2Credentials"`
}

type bwCard struct {
	CardholderName jstr `json:"cardholderName"`
	Brand          jstr `json:"brand"`
	Number         jstr `json:"number"`
	ExpMonth       jstr `json:"expMonth"`
	ExpYear        jstr `json:"expYear"`
	Code           jstr `json:"code"`
}

type bwIdentity struct {
	Title          jstr `json:"title"`
	FirstName      jstr `json:"firstName"`
	MiddleName     jstr `json:"middleName"`
	LastName       jstr `json:"lastName"`
	Address1       jstr `json:"address1"`
	Address2       jstr `json:"address2"`
	Address3       jstr `json:"address3"`
	City           jstr `json:"city"`
	State          jstr `json:"state"`
	PostalCode     jstr `json:"postalCode"`
	Country        jstr `json:"country"`
	Company        jstr `json:"company"`
	Email          jstr `json:"email"`
	Phone          jstr `json:"phone"`
	SSN            jstr `json:"ssn"`
	Username       jstr `json:"username"`
	PassportNumber jstr `json:"passportNumber"`
	LicenseNumber  jstr `json:"licenseNumber"`
}

type bwSSHKey struct {
	PrivateKey     jstr `json:"privateKey"`
	PublicKey      jstr `json:"publicKey"`
	KeyFingerprint jstr `json:"keyFingerprint"`
}

func readBitwarden(b *builder, data []byte, opts Options) error {
	var ex bwExport
	if err := json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &ex); err != nil {
		return jsonError("the Bitwarden export", err)
	}
	if ex.Encrypted {
		if !ex.PasswordProtected {
			return fmt.Errorf("%w: this Bitwarden export is encrypted with the account's key, which only Bitwarden can read; "+
				"export again choosing \"password protected\" or unencrypted JSON", ErrUnsupported)
		}
		plain, err := bwUnlock(&ex, opts.Passphrase)
		if err != nil {
			return err
		}
		defer clear(plain)
		b.crypted = true
		ex = bwExport{}
		if err := json.Unmarshal(plain, &ex); err != nil {
			return jsonError("the Bitwarden export inside the encryption", err)
		}
	}
	folders := map[string]string{}
	for _, f := range append(ex.Folders, ex.Collections...) {
		folders[string(f.ID)] = string(f.Name)
	}
	for i := range ex.Items {
		it := &ex.Items[i]
		if it.DeletedDate != "" {
			b.trashed++
			continue
		}
		folder := folders[string(it.FolderID)]
		if folder == "" && len(it.CollectionIDs) > 0 {
			folder = folders[string(it.CollectionIDs[0])]
		}
		b.add(bwDraft(it, splitPath(folder)))
	}
	return nil
}

func bwDraft(it *bwItem, folder []string) *draft {
	d := &draft{folder: folder, title: string(it.Name), history: len(it.PasswordHistory) > 0, attachments: len(it.Attachments)}
	switch it.Type {
	case 1:
		d.kind = kLogin
		if l := it.Login; l != nil {
			d.set(fUsername, svcore.FieldText, string(l.Username))
			d.set(fPassword, svcore.FieldConcealed, string(l.Password))
			for _, u := range l.URIs {
				d.url(string(u.URI))
			}
			d.otp(string(l.TOTP), string(it.Name), string(l.Username))
			d.passkeys = len(l.Fido2Credentials)
		}
	case 2:
		d.kind = kNote
	case 3:
		d.kind = kCard
		if c := it.Card; c != nil {
			d.set(fCardholder, svcore.FieldText, string(c.CardholderName))
			d.set(fNumber, svcore.FieldConcealed, string(c.Number))
			d.set(fExpiry, svcore.FieldText, expiry(string(c.ExpMonth), string(c.ExpYear)))
			d.set(fCVV, svcore.FieldConcealed, string(c.Code))
			d.set(fBrand, svcore.FieldText, string(c.Brand))
		}
	case 4:
		d.kind = kIdentity
		if p := it.Identity; p != nil {
			d.set("title", svcore.FieldText, string(p.Title))
			d.set("first_name", svcore.FieldText, string(p.FirstName))
			d.set("middle_name", svcore.FieldText, string(p.MiddleName))
			d.set("last_name", svcore.FieldText, string(p.LastName))
			d.set("company", svcore.FieldText, string(p.Company))
			d.set(fEmail, svcore.FieldEmail, string(p.Email))
			d.set("phone", svcore.FieldText, string(p.Phone))
			d.set(fUsername, svcore.FieldText, string(p.Username))
			d.set("address", svcore.FieldText, joinLines(string(p.Address1), string(p.Address2), string(p.Address3)))
			d.set("city", svcore.FieldText, string(p.City))
			d.set("state", svcore.FieldText, string(p.State))
			d.set("postal_code", svcore.FieldText, string(p.PostalCode))
			d.set("country", svcore.FieldText, string(p.Country))
			d.set("ssn", svcore.FieldConcealed, string(p.SSN))
			d.set("passport_number", svcore.FieldConcealed, string(p.PassportNumber))
			d.set("license_number", svcore.FieldConcealed, string(p.LicenseNumber))
		}
	case 5:
		d.kind = kSSHKey
		if k := it.SSHKey; k != nil {
			d.set(fPrivateKey, svcore.FieldKey, string(k.PrivateKey))
			d.set(fPublicKey, svcore.FieldText, string(k.PublicKey))
			d.set("fingerprint", svcore.FieldText, string(k.KeyFingerprint))
		}
	default:
		d.kind = kGeneric
		d.lost = append(d.lost, fmt.Sprintf("a Bitwarden item of type %d, which secretvault does not know: only its name, notes and custom fields were imported", it.Type))
	}
	d.notes(string(it.Notes))
	for _, f := range it.Fields {
		switch f.Type {
		case 1:
			d.set(string(f.Name), svcore.FieldConcealed, string(f.Value))
		case 3: // linked to another field of the item: no value of its own
		default:
			d.set(string(f.Name), svcore.FieldText, string(f.Value))
		}
	}
	return d
}

// bwUnlock decrypts a password-protected export's data.
func bwUnlock(ex *bwExport, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrPassphrase
	}
	var key []byte
	switch ex.KdfType {
	case 0:
		if ex.KdfIterations < 1 || ex.KdfIterations > 10_000_000 {
			return nil, fmt.Errorf("%w: PBKDF2 with %d iterations", ErrUnsupported, ex.KdfIterations)
		}
		var err error
		if key, err = pbkdf2.Key(sha256.New, string(password), []byte(ex.Salt), ex.KdfIterations, 32); err != nil {
			return nil, err
		}
	case 1:
		if ex.KdfIterations < 1 || ex.KdfIterations > 100 || ex.KdfMemory < 1 || ex.KdfMemory > 4096 ||
			ex.KdfParallelism < 1 || ex.KdfParallelism > 64 {
			return nil, fmt.Errorf("%w: Argon2id t=%d m=%dMiB p=%d", ErrUnsupported, ex.KdfIterations, ex.KdfMemory, ex.KdfParallelism)
		}
		salt := sha256.Sum256([]byte(ex.Salt))
		key = argon2.IDKey(password, salt[:], uint32(ex.KdfIterations), uint32(ex.KdfMemory)*1024, uint8(ex.KdfParallelism), 32)
	default:
		return nil, fmt.Errorf("%w: Bitwarden key derivation %d", ErrUnsupported, ex.KdfType)
	}
	defer clear(key)
	encKey, err := hkdf.Expand(sha256.New, key, "enc", 32)
	if err != nil {
		return nil, err
	}
	defer clear(encKey)
	macKey, err := hkdf.Expand(sha256.New, key, "mac", 32)
	if err != nil {
		return nil, err
	}
	defer clear(macKey)
	check, err := bwDecrypt(ex.EncKeyValidation, encKey, macKey)
	if err != nil {
		return nil, err
	}
	clear(check)
	return bwDecrypt(ex.Data, encKey, macKey)
}

// bwDecrypt opens a type-2 cipher string, "2.iv|ciphertext|mac".
func bwDecrypt(s string, encKey, macKey []byte) ([]byte, error) {
	typ, rest, ok := strings.Cut(s, ".")
	if !ok || typ != "2" {
		return nil, fmt.Errorf("%w: Bitwarden cipher string of type %q", ErrUnsupported, typ)
	}
	parts := strings.Split(rest, "|")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed Bitwarden cipher string", ErrFormat)
	}
	var raw [3][]byte
	for i, p := range parts {
		var err error
		if raw[i], err = base64.StdEncoding.DecodeString(p); err != nil {
			return nil, fmt.Errorf("%w: malformed Bitwarden cipher string", ErrFormat)
		}
	}
	iv, ct, tag := raw[0], raw[1], raw[2]
	m := hmac.New(sha256.New, macKey)
	m.Write(iv)
	m.Write(ct)
	if !hmac.Equal(m.Sum(nil), tag) {
		return nil, ErrWrongKey
	}
	if len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: malformed Bitwarden cipher string", ErrFormat)
	}
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ct)
	plain, err := unpad(out, aes.BlockSize)
	if err != nil {
		clear(out)
		return nil, fmt.Errorf("%w: bad padding in an authenticated Bitwarden cipher string", ErrFormat)
	}
	return plain, nil
}

// unpad strips PKCS#7 padding.
func unpad(b []byte, size int) ([]byte, error) {
	if len(b) == 0 || len(b)%size != 0 {
		return nil, ErrFormat
	}
	n := int(b[len(b)-1])
	if n == 0 || n > size {
		return nil, ErrFormat
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, ErrFormat
		}
	}
	return b[:len(b)-n], nil
}

// expiry writes a card's expiry as MM/YYYY from a month and a year as
// people type them ("1" or "01"; "27" or "2027").
func expiry(month, year string) string {
	month, year = strings.TrimSpace(month), strings.TrimSpace(year)
	if len(month) == 1 {
		month = "0" + month
	}
	if len(year) == 2 {
		year = "20" + year
	}
	switch {
	case month == "" && year == "":
		return ""
	case month == "":
		return year
	case year == "":
		return month
	}
	return month + "/" + year
}

// joinLines joins the non-empty parts of an address, one per line.
func joinLines(parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, "\n")
}
