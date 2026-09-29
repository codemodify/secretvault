package svimport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/codemodify/secretvault/svcore"
)

// Proton Pass's export: a zip holding "Proton Pass/data.json" (or that
// JSON alone): vaults (keyed by share id) → items → data, whose type is
// login, note, alias, creditCard, identity, sshKey, wifi or custom, with
// metadata (name, note), type-specific content and extra fields. Vaults
// become folders. An export encrypted with a passphrase is OpenPGP, which
// Import refuses until milestone M5.

type ppExport struct {
	Encrypted bool               `json:"encrypted"`
	Vaults    map[string]ppVault `json:"vaults"`
}

type ppVault struct {
	Name  string   `json:"name"`
	Items []ppItem `json:"items"`
}

type ppItem struct {
	State      int    `json:"state"` // 1 active, 2 trashed
	AliasEmail string `json:"aliasEmail"`
	Data       struct {
		Type     string `json:"type"`
		Metadata struct {
			Name string `json:"name"`
			Note string `json:"note"`
		} `json:"metadata"`
		ExtraFields []ppField                  `json:"extraFields"`
		Content     map[string]json.RawMessage `json:"content"`
	} `json:"data"`
	Files []json.RawMessage `json:"files"`
}

type ppField struct {
	FieldName string `json:"fieldName"`
	Type      string `json:"type"` // text, hidden, totp, timestamp
	Data      struct {
		Content   string `json:"content"`
		TOTPURI   string `json:"totpUri"`
		Timestamp any    `json:"timestamp"`
	} `json:"data"`
}

type ppSection struct {
	SectionName   string    `json:"sectionName"`
	SectionFields []ppField `json:"sectionFields"`
}

func readProtonPass(b *builder, data []byte) error {
	raw := data
	var names []string
	if bytes.HasPrefix(data, zipSignature) {
		var err error
		raw, names, err = zipMember(data, func(n string) bool { return n == "data.json" || strings.HasSuffix(n, "/data.json") })
		if err != nil {
			return err
		}
		defer clear(raw)
	}
	if isOpenPGP(raw) {
		return ErrOpenPGP
	}
	var ex ppExport
	if err := json.Unmarshal(bytes.TrimPrefix(raw, utf8BOM), &ex); err != nil {
		return jsonError("Proton Pass data.json", err)
	}
	if ex.Encrypted {
		return ErrOpenPGP
	}
	if ex.Vaults == nil {
		return fmt.Errorf("%w: Proton Pass data.json holds no vaults", ErrFormat)
	}
	ids := make([]string, 0, len(ex.Vaults))
	for id := range ex.Vaults {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(x, y string) int {
		if c := strings.Compare(ex.Vaults[x].Name, ex.Vaults[y].Name); c != 0 {
			return c
		}
		return strings.Compare(x, y)
	})
	for _, id := range ids {
		v := ex.Vaults[id]
		for i := range v.Items {
			it := &v.Items[i]
			if it.State == 2 {
				b.trashed++
				continue
			}
			b.add(ppDraft(it, []string{v.Name}))
		}
	}
	if n := filesUnder(names, "files/"); n > 0 {
		b.warn("the export holds %s, which were not imported", plural(n, "attached file"))
	}
	return nil
}

func ppDraft(it *ppItem, folder []string) *draft {
	c := it.Data.Content
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(c[k], &s)
		return s
	}
	d := &draft{folder: folder, title: it.Data.Metadata.Name, attachments: len(it.Files)}
	switch it.Data.Type {
	case "login":
		d.kind = kLogin
		user, email := str("itemUsername"), str("itemEmail")
		if user == "" && email == "" {
			user = str("username") // exports before usernames and emails were split
		}
		if user == "" {
			user, email = email, ""
		}
		d.set(fUsername, svcore.FieldText, user)
		d.set(fEmail, svcore.FieldEmail, email)
		d.set(fPassword, svcore.FieldConcealed, str("password"))
		var urls []string
		_ = json.Unmarshal(c["urls"], &urls)
		for _, u := range urls {
			d.url(u)
		}
		d.otp(str("totpUri"), it.Data.Metadata.Name, user)
		var passkeys []json.RawMessage
		_ = json.Unmarshal(c["passkeys"], &passkeys)
		d.passkeys = len(passkeys)
	case "note":
		d.kind = kNote
	case "alias":
		d.kind = kLogin
		d.set(fUsername, svcore.FieldText, it.AliasEmail)
	case "creditCard":
		d.kind = kCard
		d.set(fCardholder, svcore.FieldText, str("cardholderName"))
		d.set(fNumber, svcore.FieldConcealed, str("number"))
		if y, m, ok := strings.Cut(str("expirationDate"), "-"); ok {
			d.set(fExpiry, svcore.FieldText, expiry(m, y))
		} else {
			d.set(fExpiry, svcore.FieldText, str("expirationDate"))
		}
		d.set(fCVV, svcore.FieldConcealed, str("verificationNumber"))
		d.set(fPIN, svcore.FieldConcealed, str("pin"))
	case "identity":
		d.kind = kIdentity
		ppIdentity(d, c)
	case "sshKey":
		d.kind = kSSHKey
		d.set(fPrivateKey, svcore.FieldKey, str("privateKey"))
		d.set(fPublicKey, svcore.FieldText, str("publicKey"))
		d.set("fingerprint", svcore.FieldText, str("fingerprint"))
	case "wifi":
		d.kind = kGeneric
		d.set("ssid", svcore.FieldText, str("ssid"))
		d.set(fPassword, svcore.FieldConcealed, str("password"))
		var sec any
		if json.Unmarshal(c["security"], &sec) == nil && sec != nil {
			d.set("security", svcore.FieldText, fmt.Sprint(sec))
		}
	default: // custom, and types newer than this reader
		d.kind = kGeneric
	}
	d.notes(it.Data.Metadata.Note)
	ppFields(d, it.Data.ExtraFields)
	var sections []ppSection
	_ = json.Unmarshal(c["sections"], &sections)
	for _, s := range sections {
		ppFields(d, s.SectionFields)
	}
	return d
}

// ppIdentity maps an identity's content: the well-known fields by name,
// the rest (and the "extra" field lists) as they are.
func ppIdentity(d *draft, c map[string]json.RawMessage) {
	known := []struct{ key, name, typ string }{
		{"fullName", "full_name", svcore.FieldText},
		{"firstName", "first_name", svcore.FieldText},
		{"middleName", "middle_name", svcore.FieldText},
		{"lastName", "last_name", svcore.FieldText},
		{"birthdate", "birth_date", svcore.FieldText},
		{"gender", "gender", svcore.FieldText},
		{"email", fEmail, svcore.FieldEmail},
		{"phoneNumber", "phone", svcore.FieldText},
		{"organization", "organization", svcore.FieldText},
		{"streetAddress", "address", svcore.FieldText},
		{"floor", "floor", svcore.FieldText},
		{"county", "county", svcore.FieldText},
		{"city", "city", svcore.FieldText},
		{"stateOrProvince", "state", svcore.FieldText},
		{"zipOrPostalCode", "postal_code", svcore.FieldText},
		{"countryOrRegion", "country", svcore.FieldText},
		{"socialSecurityNumber", "ssn", svcore.FieldConcealed},
		{"passportNumber", "passport_number", svcore.FieldConcealed},
		{"licenseNumber", "license_number", svcore.FieldConcealed},
		{"company", "company", svcore.FieldText},
		{"jobTitle", "job_title", svcore.FieldText},
		{"workEmail", "work_email", svcore.FieldEmail},
		{"workPhoneNumber", "work_phone", svcore.FieldText},
		{"website", "website", svcore.FieldURL},
		{"personalWebsite", "personal_website", svcore.FieldURL},
	}
	done := map[string]bool{}
	for _, k := range known {
		var s string
		_ = json.Unmarshal(c[k.key], &s)
		d.set(k.name, k.typ, s)
		done[k.key] = true
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if done[k] {
			continue
		}
		var s string
		var fields []ppField
		var sections []ppSection
		switch {
		case json.Unmarshal(c[k], &s) == nil:
			d.set(k, svcore.FieldText, s)
		case strings.HasSuffix(k, "Sections") && json.Unmarshal(c[k], &sections) == nil:
			for _, s := range sections {
				ppFields(d, s.SectionFields)
			}
		case json.Unmarshal(c[k], &fields) == nil:
			ppFields(d, fields)
		}
	}
}

func ppFields(d *draft, fields []ppField) {
	for _, f := range fields {
		switch f.Type {
		case "hidden":
			d.set(f.FieldName, svcore.FieldConcealed, f.Data.Content)
		case "totp":
			uri := firstNonEmpty(f.Data.TOTPURI, f.Data.Content)
			if uri != "" && !d.has(fOTP) {
				d.otp(uri, d.title, "")
			} else if uri != "" {
				if u, err := otpURI(uri, d.title, ""); err == nil {
					d.set(f.FieldName, svcore.FieldOTP, u)
				} else {
					d.set(f.FieldName, svcore.FieldConcealed, uri)
				}
			}
		case "timestamp":
			if f.Data.Timestamp != nil {
				d.set(f.FieldName, svcore.FieldText, fmt.Sprint(f.Data.Timestamp))
			}
		default:
			d.set(f.FieldName, svcore.FieldText, f.Data.Content)
		}
	}
}
