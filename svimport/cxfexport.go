package svimport

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// ExportCXF writes items as a CXF 1.0 document: one account, the items'
// folders as nested collections, and each item's fields as the credentials
// CXF has for them (basic-auth, totp, note, credit-card, ssh-key, api-key,
// person-name, address and the identity documents), the rest as
// custom-fields. The item's kind and attributes ride in a "secretvault/item"
// extension, so a round trip through CXF gives the same items back.
//
// The document is JSON in the clear, holding every secret: CXF expects the
// transfer protocol to protect it, and a file has none.
func ExportCXF(items []svrpc.Item, w io.Writer) error {
	h := cxfHeader{ExporterRpID: cxfRpID, ExporterDisplayName: "secretvault", Timestamp: time.Now().Unix()}
	h.Version.Major, h.Version.Minor = 1, 0
	acct := cxfAccount{ID: cxfID("account"), Collections: []cxfCollection{}, Items: []cxfItem{}}
	for i := range items {
		it := &items[i]
		ci := cxfExportItem(it)
		acct.Items = append(acct.Items, ci)
		if dir, _, ok := cutLast(it.Name, "/"); ok {
			c := cxfCollectionAt(&acct.Collections, strings.Split(dir, "/"), nil)
			c.Items = append(c.Items, cxfLinkedItem{Item: ci.ID})
		}
	}
	h.Accounts = []cxfAccount{acct}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(h)
}

// cxfCollectionAt finds or makes the collection for a folder path.
func cxfCollectionAt(cs *[]cxfCollection, path, parent []string) *cxfCollection {
	here := append(append([]string(nil), parent...), path[0])
	var c *cxfCollection
	for i := range *cs {
		if (*cs)[i].Title == path[0] {
			c = &(*cs)[i]
		}
	}
	if c == nil {
		*cs = append(*cs, cxfCollection{ID: cxfID("collection:" + strings.Join(here, "/")), Title: path[0], Items: []cxfLinkedItem{}})
		c = &(*cs)[len(*cs)-1]
	}
	if len(path) == 1 {
		return c
	}
	return cxfCollectionAt(&c.SubCollections, path[1:], here)
}

// cxfID is a stable identifier for a name, so exporting twice gives the
// same identifiers (as CXF asks) without putting the name itself in them.
func cxfID(s string) string {
	sum := sha256.Sum256([]byte("secretvault cxf id\x00" + s))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// cxfExportItem maps one item.
func cxfExportItem(it *svrpc.Item) cxfItem {
	_, title, _ := cutLast(it.Name, "/")
	ci := cxfItem{ID: cxfID("item:" + it.Name), Title: title, Tags: it.Tags, Credentials: []json.RawMessage{}}
	if it.Label != "" && it.Label != title {
		ci.Subtitle = it.Label
	}
	used := map[string]bool{}
	get := func(name string) (svrpc.Field, bool) {
		for _, f := range it.Fields {
			if f.Name == name && !used[name] && utf8.Valid(f.Value) {
				return f, true
			}
		}
		return svrpc.Field{}, false
	}
	// take returns an EditableField for the named field and marks it used.
	take := func(name, fieldType string) *cxfField {
		f, ok := get(name)
		if !ok {
			return nil
		}
		used[name] = true
		return &cxfField{FieldType: fieldType, Value: string(f.Value)}
	}
	add := func(cred map[string]any) {
		for k, v := range cred {
			if f, ok := v.(*cxfField); ok && f == nil {
				delete(cred, k)
			}
		}
		if len(cred) > 1 {
			b, _ := json.Marshal(cred)
			ci.Credentials = append(ci.Credentials, b)
		}
	}

	add(map[string]any{"type": "basic-auth", "username": take(fUsername, "string"), "password": take(fPassword, "concealed-string")})
	for _, f := range it.Fields {
		if f.Type == svcore.FieldOTP && !used[f.Name] {
			if cred := cxfTOTP(f.Value); cred != nil {
				used[f.Name] = true
				add(cred)
			}
		}
	}
	if it.Kind == kCard {
		exp, valid := take(fExpiry, "year-month"), take("valid_from", "year-month")
		for _, f := range []*cxfField{exp, valid} {
			if f != nil {
				f.Value = expiryToYearMonth(f.Value)
			}
		}
		add(map[string]any{"type": "credit-card", "number": take(fNumber, "concealed-string"), "fullName": take(fCardholder, "string"),
			"cardType": take(fBrand, "string"), "verificationNumber": take(fCVV, "concealed-string"), "pin": take(fPIN, "concealed-string"),
			"expiryDate": exp, "validFrom": valid})
	}
	if it.Kind == kSSHKey {
		if cred := cxfExportSSHKey(it, used); cred != nil {
			add(cred)
		}
	}
	if it.Kind == kAPIKey {
		key := take("key", "concealed-string")
		if key == nil {
			key = take("secret", "concealed-string")
		}
		add(map[string]any{"type": "api-key", "key": key, "username": take(fUsername, "string"), "keyType": take("key_type", "string")})
	}
	if it.Kind == kIdentity {
		add(map[string]any{"type": "person-name", "title": take("title", "string"), "given": take("first_name", "string"),
			"given2": take("middle_name", "string"), "surname": take("last_name", "string")})
		add(map[string]any{"type": "address", "streetAddress": take("address", "string"), "city": take("city", "string"),
			"territory": take("state", "subdivision-code"), "postalCode": take("postal_code", "string"),
			"country": take("country", "country-code"), "tel": take("phone", "string")})
		add(map[string]any{"type": "passport", "passportNumber": take("passport_number", "string")})
		add(map[string]any{"type": "drivers-license", "licenseNumber": take("license_number", "string")})
		add(map[string]any{"type": "identity-document", "identificationNumber": take("ssn", "string")})
	}
	add(map[string]any{"type": "note", "content": take(fNotes, "string")})

	var urls []string
	var custom []cxfField
	for _, f := range it.Fields {
		switch {
		case used[f.Name]:
		case f.Type == svcore.FieldURL && utf8.Valid(f.Value):
			urls = append(urls, string(f.Value))
		case !utf8.Valid(f.Value) || f.Type == svcore.FieldBinary:
			ext, _ := json.Marshal(map[string]string{"name": cxfExtBase64})
			custom = append(custom, cxfField{FieldType: "concealed-string", Label: f.Name,
				Value: base64.StdEncoding.EncodeToString(f.Value), Extensions: []json.RawMessage{ext}})
		default:
			custom = append(custom, cxfField{FieldType: typeToCXF(f.Type), Label: f.Name, Value: string(f.Value)})
		}
	}
	if len(custom) > 0 {
		b, _ := json.Marshal(map[string]any{"type": "custom-fields", "fields": custom})
		ci.Credentials = append(ci.Credentials, b)
	}
	if len(urls) > 0 {
		ci.Scope = &cxfScope{URLs: urls, AndroidApps: []json.RawMessage{}}
	}
	ext, _ := json.Marshal(cxfItemExt{Name: cxfExtItem, Kind: it.Kind, Attrs: it.Attrs})
	ci.Extensions = []json.RawMessage{ext}
	return ci
}

// cxfTOTP is a totp credential for an otpauth URI, or nil for keys CXF's
// TOTP cannot hold (HOTP, Steam): those go in custom fields as URIs.
func cxfTOTP(uri []byte) map[string]any {
	k, err := svotp.Parse(string(uri))
	if err != nil || k.Type != "totp" || k.Steam {
		return nil
	}
	defer k.Wipe()
	cred := map[string]any{"type": "totp", "secret": base32NoPad(k.Secret), "period": k.Period, "digits": k.Digits,
		"algorithm": strings.ToLower(k.Algorithm)}
	if k.Account != "" {
		cred["username"] = k.Account
	}
	if k.Issuer != "" {
		cred["issuer"] = k.Issuer
	}
	return cred
}

// cxfExportSSHKey writes the private key as PKCS#8 DER, as CXF requires,
// reading OpenSSH and PEM keys (with the item's passphrase if the key is
// encrypted). A key it cannot read stays in custom fields as it is.
func cxfExportSSHKey(it *svrpc.Item, used map[string]bool) map[string]any {
	var pemKey, pass []byte
	for _, f := range it.Fields {
		switch f.Name {
		case fPrivateKey:
			pemKey = f.Value
		case fPassphrase:
			pass = f.Value
		}
	}
	if pemKey == nil {
		return nil
	}
	var key any
	var err error
	if len(pass) > 0 {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(pemKey, pass)
	} else {
		key, err = ssh.ParseRawPrivateKey(pemKey)
	}
	if err != nil {
		return nil
	}
	if p, ok := key.(*ed25519.PrivateKey); ok {
		key = *p
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	defer clear(der)
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil
	}
	used[fPrivateKey], used[fPassphrase], used[fPublicKey], used["fingerprint"] = true, true, true, true
	cred := map[string]any{"type": "ssh-key", "keyType": signer.PublicKey().Type(),
		"privateKey": base64.RawURLEncoding.EncodeToString(der)}
	for _, f := range it.Fields {
		if f.Name == "comment" && utf8.Valid(f.Value) {
			cred["keyComment"] = string(f.Value)
			used["comment"] = true
		}
	}
	return cred
}

func typeToCXF(t string) string {
	switch t {
	case svcore.FieldConcealed, svcore.FieldKey, svcore.FieldOTP:
		return "concealed-string"
	case svcore.FieldEmail:
		return "email"
	}
	return cxfTypeDefault
}

// expiryToYearMonth turns MM/YYYY into CXF's YYYY-MM.
func expiryToYearMonth(s string) string {
	if m, y, ok := strings.Cut(strings.TrimSpace(s), "/"); ok {
		if len(y) == 2 {
			y = "20" + y
		}
		if n, err := strconv.Atoi(m); err == nil && len(y) == 4 {
			return y + "-" + leftPad2(n)
		}
	}
	return s
}

func leftPad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// base32NoPad writes a secret as svotp does in URIs.
func base32NoPad(b []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// cutLast splits s around the last sep.
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return "", s, false
}
