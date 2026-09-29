package svimport

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/codemodify/secretvault/svcore"
)

// CSV exports, told apart by their header row:
//   - Chrome and Edge: name,url,username,password,note
//   - Firefox: url,username,password,httpRealm,formActionOrigin,guid,
//     timeCreated,timeLastUsed,timePasswordChanged
//   - Safari: Title,URL,Username,Password,Notes,OTPAuth
//   - Bitwarden: folder,favorite,type,name,notes,fields,reprompt,login_uri,
//     login_username,login_password,login_totp (collections in place of
//     folder for an organisation)
//   - KeePassXC: Group,Title,Username,Password,URL,Notes,TOTP,Icon,
//     Last Modified,Created
//   - anything else with recognisable column names (LastPass, 1Password,
//     hand-made files): title/name, url/website, username/login/email,
//     password, notes/note, otp/totp, folder/group. Other non-empty
//     columns become text fields.

// csvRoles maps column names (lowercased) to what they hold.
var csvRoles = map[string]string{
	"title": "title", "name": "title", "account": "title", "item": "title", "item name": "title",
	"url": "url", "urls": "url", "website": "url", "web site": "url", "uri": "url", "login_uri": "url", "login url": "url", "hostname": "url",
	"username": "username", "user name": "username", "user": "username", "login": "username", "login_username": "username",
	"login name": "username", "email": "username", "e-mail": "username",
	"password": "password", "pass": "password", "login_password": "password",
	"notes": "notes", "note": "notes", "comments": "notes", "comment": "notes", "extra": "notes",
	"otp": "otp", "totp": "otp", "otpauth": "otp", "login_totp": "otp", "one-time password": "otp", "2fa": "otp",
	"folder": "folder", "group": "folder", "grouping": "folder", "category": "folder", "path": "folder", "collections": "folder",
	"tags": "tags", "tag": "tags",
	"type": "type", "fields": "fields",
	// Columns that are bookkeeping, not data.
	"favorite": "-", "fav": "-", "reprompt": "-", "icon": "-", "guid": "-", "httprealm": "-", "formactionorigin": "-",
	"timecreated": "-", "timelastused": "-", "timepasswordchanged": "-", "last modified": "-", "created": "-",
	"modified": "-", "archived": "-", "archiveddate": "-",
}

type csvFlavour int

const (
	csvGeneric csvFlavour = iota
	csvFirefox
	csvBitwarden
	csvKeePassXC
)

func readCSV(b *builder, data []byte) error {
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, utf8BOM)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("%w: CSV has no header row: %v", ErrFormat, err)
	}
	roles := make([]string, len(header))
	cols := map[string]bool{}
	known := 0
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		cols[h] = true
		roles[i] = csvRoles[h]
		if roles[i] != "" && roles[i] != "-" {
			known++
		}
	}
	if known < 2 || !(slices.Contains(roles, "password") || slices.Contains(roles, "otp")) {
		return fmt.Errorf("%w: the CSV header names no password or OTP column", ErrFormat)
	}
	flavour := csvGeneric
	switch {
	case cols["httprealm"] && cols["formactionorigin"]:
		flavour = csvFirefox
	case cols["login_uri"] || cols["login_password"]:
		flavour = csvBitwarden
	case cols["group"] && cols["title"] && cols["totp"] && cols["last modified"]:
		flavour = csvKeePassXC
	}
	for line := 2; ; line++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: CSV line %d: %v", ErrFormat, line, err)
		}
		d := csvDraft(header, roles, rec, flavour)
		if d != nil {
			b.add(d)
		}
	}
	return nil
}

// csvDraft reads one row; nil for a row with nothing in it.
func csvDraft(header, roles, rec []string, flavour csvFlavour) *draft {
	d := &draft{}
	var otps []string
	empty := true
	for i, v := range rec {
		if i >= len(roles) || strings.TrimSpace(v) == "" {
			continue
		}
		empty = false
		switch roles[i] {
		case "title":
			if d.title == "" {
				d.title = v
			}
		case "url":
			if flavour == csvFirefox && strings.HasPrefix(v, "chrome://") {
				return nil // Firefox's own account, not a site
			}
			if v == "http://sn" {
				d.kind = kNote // LastPass marks secure notes so
				continue
			}
			if flavour == csvBitwarden {
				for _, u := range strings.Split(v, ",") {
					d.url(u)
				}
			} else {
				d.url(v)
			}
		case "username":
			if !d.has(fUsername) {
				d.set(fUsername, svcore.FieldText, v)
			} else {
				d.set(strings.TrimSpace(header[i]), svcore.FieldText, v)
			}
		case "password":
			d.set(fPassword, svcore.FieldConcealed, v)
		case "notes":
			d.notes(v)
		case "otp":
			otps = append(otps, v)
		case "folder":
			d.folder = splitPath(v)
			if flavour == csvKeePassXC && len(d.folder) > 0 {
				d.folder = d.folder[1:] // the database's root group
			}
		case "tags":
			d.tags = append(d.tags, strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' })...)
		case "type":
			switch {
			case flavour != csvBitwarden:
				d.set(strings.TrimSpace(header[i]), svcore.FieldText, v)
			case v == "note":
				d.kind = kNote
			}
		case "fields":
			if flavour == csvBitwarden {
				for _, l := range strings.Split(v, "\n") {
					k, val, _ := strings.Cut(l, ": ")
					d.set(k, svcore.FieldText, val)
				}
			} else {
				d.set(strings.TrimSpace(header[i]), svcore.FieldText, v)
			}
		case "-":
		default:
			d.set(strings.TrimSpace(header[i]), svcore.FieldText, v)
		}
	}
	if empty {
		return nil
	}
	if strings.TrimSpace(d.title) == "" {
		d.title = csvTitle(d)
	}
	user := ""
	if f, ok := fieldValue(d, fUsername); ok {
		user = f
	}
	for _, o := range otps {
		d.otp(o, d.title, user)
	}
	return d
}

// csvTitle names a row that has no title: by its site, else its username.
func csvTitle(d *draft) string {
	if u, ok := fieldValue(d, fURL); ok {
		if p, err := url.Parse(u); err == nil && p.Hostname() != "" {
			return p.Hostname()
		}
		return u
	}
	if u, ok := fieldValue(d, fUsername); ok {
		return u
	}
	return ""
}

func fieldValue(d *draft, name string) (string, bool) {
	for _, f := range d.fields {
		if f.Name == name {
			return string(f.Value), true
		}
	}
	return "", false
}
