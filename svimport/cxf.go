package svimport

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// The FIDO Alliance's Credential Exchange Format, version 1.0
// (https://fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html): a header
// with accounts, each holding collections (folders, nested) and items,
// each item a title, a scope (URLs), tags and a list of typed credentials.
// Reading maps an item's credentials onto one secretvault item, choosing
// the kind from what it holds; ExportCXF writes the same shapes back.
// A passkey credential becomes a passkey item of its own (svext's layout),
// beside the item's other credentials; files are left behind with a
// warning.

type cxfHeader struct {
	Version struct {
		Major int `json:"major"`
		Minor int `json:"minor"`
	} `json:"version"`
	ExporterRpID        string       `json:"exporterRpId"`
	ExporterDisplayName string       `json:"exporterDisplayName"`
	Timestamp           int64        `json:"timestamp"`
	Accounts            []cxfAccount `json:"accounts"`
}

type cxfAccount struct {
	ID          string          `json:"id"`
	Username    string          `json:"username"`
	Email       string          `json:"email"`
	FullName    string          `json:"fullName,omitempty"`
	Collections []cxfCollection `json:"collections"`
	Items       []cxfItem       `json:"items"`
}

type cxfCollection struct {
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	Items          []cxfLinkedItem `json:"items"`
	SubCollections []cxfCollection `json:"subCollections,omitempty"`
}

type cxfLinkedItem struct {
	Item    string `json:"item"`
	Account string `json:"account,omitempty"`
}

type cxfItem struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Subtitle    string            `json:"subtitle,omitempty"`
	Scope       *cxfScope         `json:"scope,omitempty"`
	Credentials []json.RawMessage `json:"credentials"`
	Tags        []string          `json:"tags,omitempty"`
	Extensions  []json.RawMessage `json:"extensions,omitempty"`
	CreationAt  int64             `json:"creationAt,omitempty"`
}

type cxfScope struct {
	URLs        []string          `json:"urls"`
	AndroidApps []json.RawMessage `json:"androidApps"`
}

// cxfField is the spec's EditableField.
type cxfField struct {
	ID         string            `json:"id,omitempty"`
	FieldType  string            `json:"fieldType"`
	Value      string            `json:"value"`
	Label      string            `json:"label,omitempty"`
	Extensions []json.RawMessage `json:"extensions,omitempty"`
}

// secretvault's own extensions: the item's kind and attributes, and a
// field value carried in base64 because it is not text.
const (
	cxfRpID        = "secretvault"
	cxfExtItem     = cxfRpID + "/item"
	cxfExtBase64   = cxfRpID + "/base64"
	cxfTypeDefault = "string"
)

type cxfItemExt struct {
	Name  string            `json:"name"`
	Item  string            `json:"item,omitempty"` // the item's own name
	Kind  string            `json:"kind,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// cxfCred is one credential, kept as its JSON members.
type cxfCred map[string]json.RawMessage

func (c cxfCred) str(k string) string {
	var s string
	_ = json.Unmarshal(c[k], &s)
	return s
}

func (c cxfCred) num(k string) int {
	var n int
	_ = json.Unmarshal(c[k], &n)
	return n
}

// field reads an EditableField member; ok is false when it is absent.
func (c cxfCred) field(k string) (cxfField, bool) {
	var f cxfField
	if raw, ok := c[k]; !ok || json.Unmarshal(raw, &f) != nil {
		return f, false
	}
	return f, true
}

func readCXF(b *builder, data []byte) error {
	var h cxfHeader
	if err := json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &h); err != nil {
		return jsonError("the CXF document", err)
	}
	if h.Version.Major != 1 {
		return fmt.Errorf("%w: CXF version %d.%d (this reads 1.x)", ErrUnsupported, h.Version.Major, h.Version.Minor)
	}
	for _, acct := range h.Accounts {
		folders := map[string][]string{}
		var walk func(cs []cxfCollection, path []string)
		walk = func(cs []cxfCollection, path []string) {
			for _, c := range cs {
				p := append(append([]string(nil), path...), c.Title)
				for _, li := range c.Items {
					if _, seen := folders[li.Item]; !seen && (li.Account == "" || li.Account == acct.ID) {
						folders[li.Item] = p
					}
				}
				walk(c.SubCollections, p)
			}
		}
		walk(acct.Collections, nil)
		top := []string(nil)
		if len(h.Accounts) > 1 {
			top = []string{firstNonEmpty(acct.Username, acct.Email, acct.FullName, "account")}
		}
		for i := range acct.Items {
			it := &acct.Items[i]
			for _, d := range cxfDrafts(b, it, append(append([]string(nil), top...), folders[it.ID]...)) {
				b.add(d)
			}
		}
	}
	return nil
}

// cxfDrafts are the items one CXF item becomes: one for its credentials,
// and one for each passkey it holds. An item that is a passkey and no
// more is that passkey alone.
func cxfDrafts(b *builder, it *cxfItem, folder []string) []*draft {
	d, passkeys, seen := cxfDraft(it, folder)
	if seen == 0 {
		return []*draft{d}
	}
	var out []*draft
	onlyURLs := true
	for _, f := range d.fields {
		onlyURLs = onlyURLs && f.Type == svcore.FieldURL
	}
	if !onlyURLs {
		out = append(out, d)
	} else if len(passkeys) == 0 {
		// Nothing but passkeys, none of them usable: no item, only why.
		for _, l := range d.lost {
			b.warn("%s: %s", it.Title, l)
		}
		return nil
	}
	for i, p := range passkeys {
		p.folder, p.title, p.tags = folder, it.Title, it.Tags
		if !onlyURLs {
			p.title = it.Title + " passkey"
		}
		if len(passkeys) == 1 && onlyURLs {
			p.name, p.attrs = d.name, d.attrs // its own secretvault/item extension
		}
		if onlyURLs && i == 0 {
			p.lost = append(p.lost, d.lost...) // the item is not imported but for its passkeys
		}
		out = append(out, p)
	}
	return out
}

func cxfDraft(it *cxfItem, folder []string) (*draft, []*draft, int) {
	d := &draft{folder: folder, title: it.Title, tags: it.Tags}
	has := map[string]bool{}
	var passkeys []*draft
	seen := 0
	for _, raw := range it.Credentials {
		var c cxfCred
		if json.Unmarshal(raw, &c) != nil {
			continue
		}
		t := c.str("type")
		if t == "passkey" {
			seen++
			if p, why := cxfPasskey(c, it.CreationAt); p != nil {
				passkeys = append(passkeys, p)
			} else {
				d.lost = append(d.lost, why)
			}
			continue
		}
		has[t] = true
		cxfCredential(d, t, c)
	}
	if it.Scope != nil {
		for _, u := range it.Scope.URLs {
			d.url(u)
		}
	}
	switch {
	case has["basic-auth"]:
		d.kind = kLogin
	case has["credit-card"]:
		d.kind = kCard
	case has["ssh-key"]:
		d.kind = kSSHKey
	case has["api-key"]:
		d.kind = kAPIKey
	case has["person-name"] || has["address"] || has["passport"] || has["drivers-license"] || has["identity-document"]:
		d.kind = kIdentity
	case has["generated-password"]:
		d.kind = kPassword
	case has["totp"] && onlyOTPAndNotes(d):
		d.kind = kOTP
	case has["totp"]:
		d.kind = kLogin
	case has["note"] && len(d.fields) == 1:
		d.kind = kNote
	default:
		d.kind = kGeneric
	}
	for _, raw := range it.Extensions {
		var x cxfItemExt
		if json.Unmarshal(raw, &x) == nil && x.Name == cxfExtItem {
			if x.Kind != "" {
				d.kind = x.Kind
			}
			d.name, d.attrs = x.Item, x.Attrs
		}
	}
	if d.kind == svext.PasskeyKind {
		d.kind = "" // what its credentials make it, now its passkey is apart
	}
	return d, passkeys, seen
}

// passkeyText is a passkey's account name as the extension would take it:
// no control characters, at most 256 bytes, cut at a character.
func passkeyText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	for len(s) > svext.MaxUserName {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// cxfPasskey is a passkey credential as a passkey item, or nil and why
// not: a key secretvault cannot sign with, or a credential it cannot read.
func cxfPasskey(c cxfCred, created int64) (*draft, string) {
	const unreadable = "a passkey that could not be read (its site, credential ID or user handle)"
	r := &svext.PasskeyRecord{RPID: strings.ToLower(strings.TrimSpace(c.str("rpId"))), UserName: passkeyText(c.str("username")),
		DisplayName: passkeyText(c.str("userDisplayName"))}
	var err error
	if r.CredentialID, err = svext.UnB64(c.str("credentialId")); err != nil || len(r.CredentialID) == 0 || len(r.CredentialID) > svext.MaxCredentialID {
		return nil, unreadable
	}
	if r.UserHandle, err = svext.UnB64(c.str("userHandle")); err != nil || len(r.UserHandle) > svext.MaxUserHandle {
		return nil, unreadable
	}
	if !svext.ValidRPID(r.RPID) {
		return nil, unreadable
	}
	const badKey = "a passkey whose key secretvault cannot use (it makes and uses P-256 and Ed25519 keys)"
	if r.PrivateKey, err = svext.UnB64(c.str("key")); err != nil {
		return nil, badKey
	}
	defer clear(r.PrivateKey)
	kp, err := svext.PublicOf(r.PrivateKey)
	if err != nil {
		return nil, badKey
	}
	r.Alg = kp.Alg
	if created > 0 {
		r.Created = time.Unix(created, 0).UTC()
	}
	p := &draft{kind: svext.PasskeyKind}
	for _, f := range r.Fields() {
		p.fields = append(p.fields, svrpc.Field{Name: f.Name, Type: f.Type, Value: f.Value})
	}
	return p, ""
}

// onlyOTPAndNotes reports a draft holding an OTP key and at most notes: an
// authenticator entry.
func onlyOTPAndNotes(d *draft) bool {
	for _, f := range d.fields {
		if f.Name != fOTP && f.Name != fNotes {
			return false
		}
	}
	return true
}

// cxfCredential adds one credential's fields.
func cxfCredential(d *draft, t string, c cxfCred) {
	// put adds the EditableField member k as field name, of the given
	// type, or of the type its fieldType says when typ is "".
	put := func(k, name, typ string) {
		if f, ok := c.field(k); ok {
			if typ == "" {
				typ = cxfToType(f.FieldType)
			}
			d.set(name, typ, f.Value)
		}
	}
	switch t {
	case "basic-auth":
		put("username", fUsername, svcore.FieldText)
		put("password", fPassword, svcore.FieldConcealed)
	case "totp":
		secret, err := svotp.DecodeSecret(c.str("secret"))
		if err != nil {
			d.lost = append(d.lost, "a TOTP key that could not be read")
			return
		}
		k := &svotp.Key{Type: "totp", Issuer: c.str("issuer"), Account: c.str("username"), Secret: secret,
			Algorithm: hashName(c.str("algorithm")), Digits: c.num("digits"), Period: c.num("period")}
		uri, err := otpKeyURI(k)
		k.Wipe()
		if err != nil {
			d.lost = append(d.lost, "a TOTP key with parameters secretvault cannot use")
			return
		}
		d.set(fOTP, svcore.FieldOTP, uri)
	case "note":
		put("content", fNotes, svcore.FieldText)
	case "credit-card":
		put("fullName", fCardholder, svcore.FieldText)
		put("number", fNumber, svcore.FieldConcealed)
		if f, ok := c.field("expiryDate"); ok {
			d.set(fExpiry, svcore.FieldText, yearMonthToExpiry(f.Value))
		}
		if f, ok := c.field("validFrom"); ok {
			d.set("valid_from", svcore.FieldText, yearMonthToExpiry(f.Value))
		}
		put("verificationNumber", fCVV, svcore.FieldConcealed)
		put("pin", fPIN, svcore.FieldConcealed)
		put("cardType", fBrand, svcore.FieldText)
	case "ssh-key":
		cxfSSHKey(d, c)
	case "api-key":
		put("key", "key", svcore.FieldConcealed)
		put("username", fUsername, svcore.FieldText)
		put("keyType", "key_type", svcore.FieldText)
		put("url", fURL, svcore.FieldURL)
		put("validFrom", "valid_from", svcore.FieldText)
		put("expiryDate", "expiry_date", svcore.FieldText)
	case "address":
		put("streetAddress", "address", svcore.FieldText)
		put("city", "city", svcore.FieldText)
		put("territory", "state", svcore.FieldText)
		put("postalCode", "postal_code", svcore.FieldText)
		put("country", "country", svcore.FieldText)
		put("tel", "phone", svcore.FieldText)
	case "person-name":
		put("title", "title", svcore.FieldText)
		put("given", "first_name", svcore.FieldText)
		put("givenInformal", "nickname", svcore.FieldText)
		put("given2", "middle_name", svcore.FieldText)
		surname := strings.TrimSpace(c.fieldValue("surnamePrefix") + " " + c.fieldValue("surname"))
		d.set("last_name", svcore.FieldText, surname)
		put("surname2", "second_last_name", svcore.FieldText)
		put("credentials", "qualifications", svcore.FieldText)
		put("generation", "generation", svcore.FieldText)
	case "drivers-license":
		put("licenseNumber", "license_number", svcore.FieldConcealed)
		cxfDocument(d, c, "license")
		put("licenseClass", "license_class", svcore.FieldText)
	case "passport":
		put("passportNumber", "passport_number", svcore.FieldConcealed)
		put("passportType", "passport_type", svcore.FieldText)
		put("nationalIdentificationNumber", "national_id", svcore.FieldConcealed)
		cxfDocument(d, c, "passport")
	case "identity-document":
		put("documentNumber", "document_number", svcore.FieldConcealed)
		put("identificationNumber", "identification_number", svcore.FieldConcealed)
		cxfDocument(d, c, "document")
	case "wifi":
		put("ssid", "ssid", svcore.FieldText)
		put("passphrase", fPassword, svcore.FieldConcealed)
		put("networkSecurityType", "security", svcore.FieldText)
		put("hidden", "hidden", svcore.FieldText)
	case "generated-password":
		d.set(fPassword, svcore.FieldConcealed, c.str("password"))
	case "custom-fields":
		var fields []cxfField
		_ = json.Unmarshal(c["fields"], &fields)
		for _, f := range fields {
			name := firstNonEmpty(f.Label, c.str("label"), "field")
			if cxfIsBase64(f) {
				if v, err := base64.StdEncoding.DecodeString(f.Value); err == nil {
					d.setBytes(name, svcore.FieldBinary, v)
					continue
				}
			}
			typ := cxfToType(f.FieldType)
			if strings.HasPrefix(f.Value, "otpauth://") {
				// A key CXF's totp cannot hold (HOTP, Steam), as ExportCXF
				// writes it.
				if uri, err := otpURI(f.Value, "", ""); err == nil {
					d.set(name, svcore.FieldOTP, uri)
					continue
				}
			}
			d.set(name, typ, f.Value)
		}
	case "file":
		d.attachments++
	case "item-reference":
	default:
		d.lost = append(d.lost, fmt.Sprintf("a CXF credential of type %q, which secretvault does not know", t))
	}
}

// fieldValue is an EditableField member's value, or "".
func (c cxfCred) fieldValue(k string) string {
	f, _ := c.field(k)
	return f.Value
}

// cxfDocument adds what identity documents share.
func cxfDocument(d *draft, c cxfCred, what string) {
	for _, m := range []struct{ k, name string }{
		{"fullName", "full_name"}, {"birthDate", "birth_date"}, {"birthPlace", "birth_place"}, {"sex", "sex"},
		{"nationality", "nationality"}, {"issuingCountry", what + "_country"}, {"country", what + "_country"},
		{"territory", what + "_territory"}, {"issuingAuthority", what + "_authority"},
		{"issueDate", what + "_issued"}, {"expiryDate", what + "_expires"},
	} {
		if f, ok := c.field(m.k); ok {
			d.set(m.name, svcore.FieldText, f.Value)
		}
	}
}

// cxfSSHKey turns the PKCS#8 DER key into PEM, and derives the public key.
func cxfSSHKey(d *draft, c cxfCred) {
	der, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(c.str("privateKey"), "="))
	if err != nil || len(der) == 0 {
		d.lost = append(d.lost, "an SSH key that could not be read")
		return
	}
	defer clear(der)
	d.setBytes(fPrivateKey, svcore.FieldKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(interface{ Public() crypto.PublicKey }); ok {
			if pub, err := ssh.NewPublicKey(s.Public()); err == nil {
				d.set(fPublicKey, svcore.FieldText, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))))
				d.set("fingerprint", svcore.FieldText, ssh.FingerprintSHA256(pub))
			}
		}
	}
	d.set("comment", svcore.FieldText, c.str("keyComment"))
	for _, m := range []struct{ k, name string }{
		{"creationDate", "created"}, {"expiryDate", "expires"}, {"keyGenerationSource", "source"},
	} {
		if f, ok := c.field(m.k); ok {
			d.set(m.name, svcore.FieldText, f.Value)
		}
	}
}

// cxfToType maps a CXF fieldType onto a secretvault field type.
func cxfToType(ft string) string {
	switch ft {
	case "concealed-string":
		return svcore.FieldConcealed
	case "email":
		return svcore.FieldEmail
	}
	return svcore.FieldText
}

func cxfIsBase64(f cxfField) bool {
	for _, raw := range f.Extensions {
		var x struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &x) == nil && x.Name == cxfExtBase64 {
			return true
		}
	}
	return false
}

// yearMonthToExpiry turns CXF's YYYY-MM into MM/YYYY.
func yearMonthToExpiry(s string) string {
	if y, m, ok := strings.Cut(strings.TrimSpace(s), "-"); ok && len(y) == 4 {
		return expiry(m, y)
	}
	return s
}
