package svimport

import (
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

func TestBrowserCSVExportsImport(t *testing.T) {
	chrome := "\xef\xbb\xbfname,url,username,password,note\n" +
		"github.com,https://github.com/login,ada,gh-pass,\"line one\nline two\"\n" +
		"github.com,https://github.com/session,ada-work,gh-pass-2,\n"
	res := mustImport(t, FormatCSV, []byte(chrome), Options{Prefix: "chrome"})
	gh := item(t, res, "chrome/github.com")
	has(t, gh, "username", svcore.FieldText, "ada")
	has(t, gh, "password", svcore.FieldConcealed, "gh-pass")
	has(t, gh, "url", svcore.FieldURL, "https://github.com/login")
	has(t, gh, "notes", svcore.FieldText, "line one\nline two")
	has(t, item(t, res, "chrome/github.com (2)"), "username", svcore.FieldText, "ada-work")

	firefox := `"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
"https://www.mozilla.org","ada","moz-pass",,"https://www.mozilla.org","{0b5f8b1c}","1600000000000","1600000000000","1600000000000"
"chrome://FirefoxAccounts","sync","ignored",,,"{1}","1","1","1"
"https://intranet.example:8443","ada","basic-pass","Intranet",,"{2}","1","1","1"
`
	res = mustImport(t, FormatCSV, []byte(firefox), Options{})
	moz := item(t, res, "www.mozilla.org")
	has(t, moz, "password", svcore.FieldConcealed, "moz-pass")
	if len(moz.Fields) != 3 {
		t.Errorf("Firefox's bookkeeping columns were imported: %+v", moz.Fields)
	}
	item(t, res, "intranet.example")
	if len(res.Items) != 2 {
		t.Errorf("%d items; Firefox's own account should be skipped", len(res.Items))
	}

	safari := "Title,URL,Username,Password,Notes,OTPAuth\n" +
		"Apple (ada),https://appleid.apple.com,ada@icloud.com,apple-pass,,otpauth://totp/Apple:ada?secret=JBSWY3DPEHPK3PXP&issuer=Apple\n"
	res = mustImport(t, FormatCSV, []byte(safari), Options{})
	apple := item(t, res, "Apple (ada)")
	has(t, apple, "otp", svcore.FieldOTP, "otpauth://totp/Apple:ada?issuer=Apple&secret=JBSWY3DPEHPK3PXP")
	has(t, apple, "username", svcore.FieldText, "ada@icloud.com")
}

func TestPasswordManagerCSVExportsImport(t *testing.T) {
	bitwarden := "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
		"Work/Servers,1,login,db1,,\"port: 5432\nregion: eu\",0,\"https://db1.example,https://db1-admin.example\",root,r00t,JBSWY3DPEHPK3PXP\n" +
		",,note,Door code,4711#,,0,,,,\n"
	res := mustImport(t, FormatCSV, []byte(bitwarden), Options{})
	db := item(t, res, "Work/Servers/db1")
	has(t, db, "url2", svcore.FieldURL, "https://db1-admin.example")
	has(t, db, "port", svcore.FieldText, "5432")
	has(t, db, "region", svcore.FieldText, "eu")
	has(t, db, "otp", svcore.FieldOTP, "otpauth://totp/db1:root?issuer=db1&secret=JBSWY3DPEHPK3PXP")
	hasNot(t, db, "favorite")
	if n := item(t, res, "Door code"); n.Kind != "note" {
		t.Errorf("a Bitwarden note row became %q", n.Kind)
	}

	keepassxc := `"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Passwords/Work","VPN","ada","vpn-pass","https://vpn.example","","otpauth://totp/VPN:ada?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=VPN","0","2025-01-01T00:00:00Z","2025-01-01T00:00:00Z"
"Passwords","Top","t","p","","","","0","2025-01-01T00:00:00Z","2025-01-01T00:00:00Z"
`
	res = mustImport(t, FormatCSV, []byte(keepassxc), Options{})
	vpn := item(t, res, "Work/VPN")
	has(t, vpn, "otp", svcore.FieldOTP, "otpauth://totp/VPN:ada?issuer=VPN&secret=JBSWY3DPEHPK3PXP")
	hasNot(t, vpn, "Icon")
	item(t, res, "Top")

	lastpass := "url,username,password,totp,extra,name,grouping,fav\n" +
		"https://lastpass.com,ada,lp-pass,,a note,LastPass,Security,0\n" +
		"http://sn,,,,secure note body,Wifi,Home,0\n"
	res = mustImport(t, FormatCSV, []byte(lastpass), Options{})
	lp := item(t, res, "Security/LastPass")
	has(t, lp, "notes", svcore.FieldText, "a note")
	hasNot(t, lp, "fav")
	if n := item(t, res, "Home/Wifi"); n.Kind != "note" || len(n.Fields) != 1 {
		t.Errorf("a LastPass secure note: %+v", n)
	}

	generic := "Account;Site;Login;Pass\nignored\n"
	if _, err := Import(FormatCSV, []byte(generic), Options{}); !errors.Is(err, ErrFormat) {
		t.Errorf("a CSV without a password column: %v", err)
	}
	custom := "Title,Password,Security answer,Website\nBank,b-pass,rex,https://bank.example\n,,,\n"
	res = mustImport(t, FormatCSV, []byte(custom), Options{})
	bank := item(t, res, "Bank")
	has(t, bank, "Security answer", svcore.FieldText, "rex")
	has(t, bank, "url", svcore.FieldURL, "https://bank.example")
	if len(res.Items) != 1 {
		t.Errorf("an empty row became an item")
	}
}
