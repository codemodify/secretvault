package svmail

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

const nested = `From: Alice <alice@example.org>
To: bob@example.org
Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

This is the preamble.
--outer
Content-Type: multipart/alternative; boundary=inner

--inner
Content-Type: text/plain; charset=utf-8

Hello
--innerwith more is not a boundary
--inner--
--outer
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

caf=E9 =80=
 soft
--outer--
epilogue
`

func TestParseNested(t *testing.T) {
	for _, eol := range []string{"\n", "\r\n"} {
		raw := []byte(strings.ReplaceAll(nested, "\n", eol))
		p, err := ParseMessage(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.MediaType != "multipart/mixed" || len(p.Parts) != 2 || len(p.Problems) != 0 {
			t.Fatalf("root %s, %d parts, %q", p.MediaType, len(p.Parts), p.Problems)
		}
		alt := p.Parts[0]
		if alt.MediaType != "multipart/alternative" || len(alt.Parts) != 1 {
			t.Fatalf("alternative: %s, %d parts", alt.MediaType, len(alt.Parts))
		}
		// The part's bytes are exactly those between the boundaries, the
		// line break before the next boundary excluded.
		wantRaw := strings.ReplaceAll("Content-Type: text/plain; charset=utf-8\n\nHello\n--innerwith more is not a boundary", "\n", eol)
		if string(alt.Parts[0].Raw) != wantRaw {
			t.Fatalf("raw %q", alt.Parts[0].Raw)
		}
		if !bytes.HasPrefix(raw[bytes.Index(raw, alt.Parts[0].Raw)-len("--inner"+eol):], []byte("--inner"+eol)) {
			t.Fatal("raw is not a slice of the input")
		}
		qp := p.Parts[1]
		body, err := qp.Decoded()
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "caf\xe9 \x80 soft" {
			t.Fatalf("decoded %q", body)
		}
		text, ok, problem := decodeText(qp.Params["charset"], body)
		if !ok || problem != "" || text != "café € soft" {
			t.Fatalf("text %q %v %q", text, ok, problem)
		}
		if got := DecodeHeader(p.Header.Get("Subject")); got != "Grüße" {
			t.Fatalf("subject %q", got)
		}
	}
}

func TestParseProblems(t *testing.T) {
	// No closing boundary, a part with no header, a stray header line.
	raw := crlf("Content-Type: multipart/mixed; boundary=b\nX-Bad line\n\n--b\n\njust body\n--b\nContent-Type: text/plain\n\nlast part runs to the end\n")
	p, err := ParseMessage(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Parts) != 2 || len(p.Problems) != 2 {
		t.Fatalf("%d parts, problems %q", len(p.Parts), p.Problems)
	}
	if string(p.Parts[0].Body) != "just body" || string(p.Parts[1].Body) != "last part runs to the end\r\n" {
		t.Fatalf("bodies %q %q", p.Parts[0].Body, p.Parts[1].Body)
	}
	// Something with no header at all is all body.
	p, err = ParseMessage([]byte("hello there\nno header\n"), nil)
	if err != nil || len(p.Header) != 0 || string(p.Body) != "hello there\nno header\n" {
		t.Fatalf("%v %q", err, p.Body)
	}
	// An mbox separator is skipped.
	p, err = ParseMessage([]byte("From alice@example.org Mon Jan  1 00:00:00 2024\nSubject: x\n\nbody"), nil)
	if err != nil || p.Header.Get("Subject") != "x" || string(p.Body) != "body" {
		t.Fatalf("%v %+v", err, p)
	}
	// Folded fields keep their raw bytes.
	p, _ = ParseMessage(crlf("Subject: a\n  b\nTo: c\n\n"), nil)
	if p.Header.Get("Subject") != "a b" || string(p.Header[0].Raw) != "Subject: a\r\n  b\r\n" {
		t.Fatalf("%q %q", p.Header.Get("Subject"), p.Header[0].Raw)
	}
}

func TestParseLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString("Content-Type: multipart/mixed; boundary=x\n\n")
	for range 50 {
		b.WriteString("--x\nContent-Type: text/plain\n\nx\n")
	}
	b.WriteString("--x--\n")
	if _, err := ParseMessage([]byte(b.String()), &Limits{MaxParts: 10}); !errors.Is(err, ErrLimit) {
		t.Fatalf("parts: %v", err)
	}
	deep := ""
	for i := range 40 {
		deep += "Content-Type: multipart/mixed; boundary=b" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\n\n--b" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\n"
	}
	if _, err := ParseMessage([]byte(deep), nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("depth: %v", err)
	}
	if _, err := ParseMessage(bytes.Repeat([]byte("X-A: b\n"), 2000), nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("fields: %v", err)
	}
}

func TestCharsets(t *testing.T) {
	for _, c := range []struct {
		charset string
		in      string
		want    string
		ok      bool
		problem bool
	}{
		{"utf-8", "naïve", "naïve", true, false},
		{"UTF8", "\xff", "�", true, true},
		{"us-ascii", "plain", "plain", true, false},
		{"us-ascii", "\x93quoted\x94", "“quoted”", true, true},
		{"iso-8859-1", "\xe9t\xe9", "été", true, false},
		{"windows-1252", "\x80 \x99", "€ ™", true, false},
		{"", "abc", "abc", true, false},
		{"koi8-r", "\xf0\xd2\xc9", "", false, true},
	} {
		got, ok, problem := decodeText(c.charset, []byte(c.in))
		if got != c.want || ok != c.ok || (problem != "") != c.problem {
			t.Errorf("%s %q: got %q %v %q", c.charset, c.in, got, ok, problem)
		}
	}
}

func TestTransferEncodings(t *testing.T) {
	for _, c := range []struct {
		cte, body, want string
	}{
		{"base64", "aGVs\r\nbG8=\r\n", "hello"},
		{"base64", "aGVsbG8", "hello"},
		{"quoted-printable", "a=3Db  \r\nc=\r\nd=zz\r\n", "a=b\r\ncd=zz\r\n"},
		{"8bit", "\xe9", "\xe9"},
		{"", "x", "x"},
	} {
		p := &Part{Header: Header{{Name: "Content-Transfer-Encoding", Value: c.cte}}, Body: []byte(c.body)}
		got, err := p.Decoded()
		if err != nil || string(got) != c.want {
			t.Errorf("%s %q: %q %v", c.cte, c.body, got, err)
		}
	}
	p := &Part{Header: Header{{Name: "Content-Transfer-Encoding", Value: "x-uuencode"}}}
	if _, err := p.Decoded(); err == nil {
		t.Error("unknown encoding accepted")
	}
}

func TestEncodeQP(t *testing.T) {
	in := []byte("From here\r\ntrailing \r\nlong " + strings.Repeat("é", 60) + "\r\n.\r\n=\r\n")
	enc := encodeQP(in)
	for _, line := range strings.Split(string(enc), "\r\n") {
		if len(line) > 76 {
			t.Fatalf("line of %d: %q", len(line), line)
		}
		if strings.HasPrefix(line, "From ") || strings.HasSuffix(line, " ") {
			t.Fatalf("unsafe line %q", line)
		}
	}
	if needsEncoding(enc) {
		t.Fatal("encoded text still needs encoding")
	}
	if got := decodeQP(enc); !bytes.Equal(got, in) {
		t.Fatalf("round trip:\n%q\n%q", got, in)
	}
}

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{"a\nb\r\nc\n": "a\r\nb\r\nc\r\n", "\n": "\r\n", "x": "x", "a\r\n": "a\r\n"} {
		if got := canonical([]byte(in)); string(got) != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
