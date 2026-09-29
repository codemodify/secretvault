package svimport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcore"
)

// 1Password's 1PUX export (https://support.1password.com/1pux-format/): a
// zip holding export.data, JSON of accounts → vaults → items. Each item
// has a category (categoryUuid), an overview (title, URLs, tags) and
// details: the web form's login fields (the username and password carry a
// "designation"), notes, and sections of typed fields. Vaults become
// folders; files (documents and attachments) sit beside export.data and
// are not imported.

type opExport struct {
	Accounts []struct {
		Attrs struct {
			AccountName string `json:"accountName"`
			Name        string `json:"name"`
			Email       string `json:"email"`
		} `json:"attrs"`
		Vaults []struct {
			Attrs struct {
				Name string `json:"name"`
			} `json:"attrs"`
			Items []opItem `json:"items"`
		} `json:"vaults"`
	} `json:"accounts"`
}

type opItem struct {
	State        string `json:"state"`
	Trashed      bool   `json:"trashed"`
	CategoryUUID string `json:"categoryUuid"`
	Details      struct {
		LoginFields []struct {
			Value       string `json:"value"`
			Name        string `json:"name"`
			FieldType   string `json:"fieldType"`
			Designation string `json:"designation"`
		} `json:"loginFields"`
		NotesPlain string `json:"notesPlain"`
		Sections   []struct {
			Title  string    `json:"title"`
			Fields []opField `json:"fields"`
		} `json:"sections"`
		PasswordHistory    []json.RawMessage `json:"passwordHistory"`
		DocumentAttributes json.RawMessage   `json:"documentAttributes"`
		Password           string            `json:"password"`
	} `json:"details"`
	Overview struct {
		Title string `json:"title"`
		URL   string `json:"url"`
		URLs  []struct {
			URL string `json:"url"`
		} `json:"urls"`
		Tags []string `json:"tags"`
	} `json:"overview"`
}

type opField struct {
	Title string                     `json:"title"`
	ID    string                     `json:"id"`
	Value map[string]json.RawMessage `json:"value"`
}

// 1Password categories.
const (
	opLogin         = "001"
	opCard          = "002"
	opNote          = "003"
	opIdentity      = "004"
	opPassword      = "005"
	opDocument      = "006"
	opLicence       = "103" // driver's licence
	opPassport      = "106"
	opSSN           = "108"
	opAPICredential = "112"
	opSSHKey        = "114"
)

var opKinds = map[string]string{
	opLogin: kLogin, opCard: kCard, opNote: kNote, opIdentity: kIdentity, opPassword: kPassword,
	opLicence: kIdentity, opPassport: kIdentity, opSSN: kIdentity, opAPICredential: kAPIKey, opSSHKey: kSSHKey,
}

// opFieldNames rename a category's template fields (by field id) to
// secretvault's names.
var opFieldNames = map[string]map[string]string{
	opCard: {"cardholder": fCardholder, "ccnum": fNumber, "cvv": fCVV, "expiry": fExpiry, "type": fBrand, "pin": fPIN,
		"validFrom": "valid_from"},
	opIdentity: {"firstname": "first_name", "initial": "middle_name", "lastname": "last_name", "email": fEmail,
		"defphone": "phone", "company": "company", "birthdate": "birth_date", "username": fUsername},
	opLicence:  {"number": "license_number", "fullname": "full_name", "birthdate": "birth_date"},
	opPassport: {"number": "passport_number", "fullname": "full_name", "birthdate": "birth_date"},
	opSSN:      {"number": "ssn", "name": "full_name"},
}

// opSecretIDs are template fields that are secret though 1Password types
// them as plain strings.
var opSecretIDs = map[string]bool{"license_number": true, "passport_number": true, "ssn": true}

func read1PUX(b *builder, data []byte) error {
	raw := data
	var names []string
	if bytes.HasPrefix(data, zipSignature) {
		var err error
		raw, names, err = zipMember(data, func(n string) bool { return n == "export.data" || strings.HasSuffix(n, "/export.data") })
		if err != nil {
			return err
		}
		defer clear(raw)
	}
	var ex opExport
	if err := json.Unmarshal(bytes.TrimPrefix(raw, utf8BOM), &ex); err != nil {
		return jsonError("1PUX export.data", err)
	}
	if len(ex.Accounts) == 0 {
		return fmt.Errorf("%w: 1PUX export.data holds no account", ErrFormat)
	}
	for _, acct := range ex.Accounts {
		for _, v := range acct.Vaults {
			folder := []string{v.Attrs.Name}
			if len(ex.Accounts) > 1 {
				folder = []string{firstNonEmpty(acct.Attrs.AccountName, acct.Attrs.Name, acct.Attrs.Email), v.Attrs.Name}
			}
			for i := range v.Items {
				it := &v.Items[i]
				if it.Trashed || it.State == "trashed" || it.State == "deleted" {
					b.trashed++
					continue
				}
				b.add(opDraft(it, folder))
			}
		}
	}
	if n := filesUnder(names, "files/"); n > 0 {
		b.warn("the export holds %s (documents, attachments, icons), which were not imported", plural(n, "file"))
	}
	return nil
}

func opDraft(it *opItem, folder []string) *draft {
	cat := it.CategoryUUID
	d := &draft{kind: opKinds[cat], folder: folder, title: it.Overview.Title, tags: it.Overview.Tags,
		history: len(it.Details.PasswordHistory) > 0}
	if d.kind == "" {
		d.kind = kGeneric
	}
	if it.State == "archived" {
		d.tags = append(d.tags, "archived")
	}
	if cat == opDocument || (len(it.Details.DocumentAttributes) > 0 && string(it.Details.DocumentAttributes) != "null") {
		d.attachments++
	}
	for _, lf := range it.Details.LoginFields {
		switch {
		case lf.Designation == "username":
			d.set(fUsername, svcore.FieldText, lf.Value)
		case lf.Designation == "password":
			d.set(fPassword, svcore.FieldConcealed, lf.Value)
		case lf.FieldType == "P":
			d.set(lf.Name, svcore.FieldConcealed, lf.Value)
		case lf.FieldType == "C" || lf.FieldType == "R" || lf.FieldType == "I" || lf.FieldType == "B":
			// check boxes, radio buttons, buttons: page furniture
		default:
			d.set(lf.Name, svcore.FieldText, lf.Value)
		}
	}
	d.set(fPassword, svcore.FieldConcealed, it.Details.Password)
	for _, u := range it.Overview.URLs {
		d.url(u.URL)
	}
	d.url(it.Overview.URL)
	for _, s := range it.Details.Sections {
		for _, f := range s.Fields {
			opSectionField(d, cat, s.Title, f)
		}
	}
	d.notes(it.Details.NotesPlain)
	return d
}

// opSectionField adds one field of a section, by the type of its value.
func opSectionField(d *draft, cat, section string, f opField) {
	name := firstNonEmpty(f.Title, f.ID, section)
	if n, ok := opFieldNames[cat][f.ID]; ok {
		name = n
	}
	for typ, raw := range f.Value {
		var s string
		_ = json.Unmarshal(raw, &s)
		switch typ {
		case "concealed", "creditCardNumber":
			d.set(name, svcore.FieldConcealed, s)
		case "totp", "otp":
			d.otp(s, d.title, "")
		case "url":
			d.set(name, svcore.FieldURL, s)
		case "email":
			var e struct {
				Address string `json:"email_address"`
			}
			if s == "" && json.Unmarshal(raw, &e) == nil {
				s = e.Address
			}
			d.set(name, svcore.FieldEmail, s)
		case "date":
			var t int64
			if json.Unmarshal(raw, &t) == nil && t != 0 {
				d.set(name, svcore.FieldText, time.Unix(t, 0).UTC().Format("2006-01-02"))
			}
		case "monthYear":
			var n int
			if json.Unmarshal(raw, &n) == nil && n > 0 {
				d.set(name, svcore.FieldText, fmt.Sprintf("%02d/%04d", n%100, n/100))
			}
		case "address":
			var a struct{ Street, City, State, Zip, Country string }
			if json.Unmarshal(raw, &a) == nil {
				d.set("address", svcore.FieldText, a.Street)
				d.set("city", svcore.FieldText, a.City)
				d.set("state", svcore.FieldText, a.State)
				d.set("postal_code", svcore.FieldText, a.Zip)
				d.set("country", svcore.FieldText, strings.ToUpper(a.Country))
			}
		case "sshKey":
			var k struct {
				PrivateKey string `json:"privateKey"`
				Metadata   struct {
					PrivateKey  string `json:"privateKey"`
					PublicKey   string `json:"publicKey"`
					Fingerprint string `json:"fingerprint"`
					KeyType     string `json:"keyType"`
				} `json:"metadata"`
			}
			if json.Unmarshal(raw, &k) == nil {
				d.set(fPrivateKey, svcore.FieldKey, firstNonEmpty(k.Metadata.PrivateKey, k.PrivateKey))
				d.set(fPublicKey, svcore.FieldText, k.Metadata.PublicKey)
				d.set("fingerprint", svcore.FieldText, k.Metadata.Fingerprint)
				d.set("key_type", svcore.FieldText, k.Metadata.KeyType)
			}
		case "file":
			d.attachments++
		default: // string, phone, menu, gender, creditCardType, reference, ...
			if s == "" {
				var n json.Number
				if json.Unmarshal(raw, &n) == nil {
					s = n.String()
				} else if b, err := strconv.ParseBool(string(raw)); err == nil {
					s = strconv.FormatBool(b)
				}
			}
			typ := svcore.FieldText
			if opSecretIDs[name] || name == fPassword {
				typ = svcore.FieldConcealed
			}
			d.set(name, typ, s)
		}
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
