package svext

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFramesAreALengthThenJSON(t *testing.T) {
	var buf bytes.Buffer
	for _, m := range []string{`{"action":"a"}`, ``, `{"x":"` + strings.Repeat("y", 70000) + `"}`} {
		if err := WriteFrame(&buf, []byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{`{"action":"a"}`, ``} {
		got, err := ReadFrame(&buf)
		if err != nil || string(got) != want {
			t.Fatalf("ReadFrame = %q, %v; want %q", got, err, want)
		}
	}
	if got, err := ReadFrame(&buf); err != nil || len(got) != 70008 {
		t.Fatalf("a long frame: %d bytes, %v", len(got), err)
	}
	if _, err := ReadFrame(&buf); err != io.EOF {
		t.Fatalf("at the end: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{5, 0})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a cut length: %v", err)
	}
	WriteFrame(&buf, []byte(`{"a":1}`))
	if _, err := ReadFrame(bytes.NewReader(buf.Bytes()[:6])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a cut message: %v", err)
	}
	huge := []byte{0xff, 0xff, 0xff, 0x7f}
	if _, err := ReadFrame(bytes.NewReader(huge)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a length over the limit: %v", err)
	}
	if err := WriteFrame(io.Discard, make([]byte, MaxFrame+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("writing over the limit: %v", err)
	}
}

func TestSecretsSurviveJSONBothWays(t *testing.T) {
	for _, s := range []string{
		"hunter2", `quo"te\back/slash`, "tab\tnew\nline\x01\x1f", "ünïcödé ✓", "😀 emoji", "",
		"<script>&amp;</script>", "  ",
	} {
		// Ours out, encoding/json in.
		enc := appendSecret(nil, []byte(s))
		var back string
		if err := json.Unmarshal(enc, &back); err != nil || back != s {
			t.Errorf("appendSecret(%q) = %s, read back %q, %v", s, enc, back, err)
		}
		// encoding/json out, ours in.
		j, _ := json.Marshal(s)
		got, err := decodeSecret(j)
		if err != nil || string(got) != s {
			t.Errorf("decodeSecret(%s) = %q, %v", j, got, err)
		}
	}
	if got, _ := decodeSecret([]byte(`"😀 and é and \ud800 alone"`)); string(got) != "😀 and é and � alone" {
		t.Errorf("escapes: %q", got)
	}
	if enc := appendSecret(nil, []byte{'a', 0xff, 'b'}); !utf8.Valid(enc) || !bytes.Contains(enc, []byte(`�`)) {
		t.Errorf("invalid UTF-8 went out as %q", enc)
	}
	for _, bad := range []string{`hunter2`, `"unterminated`, `"bad \x escape"`, `"raw ` + "\n" + ` newline"`, `"\u12"`, `12`, `null`} {
		if _, err := decodeSecret([]byte(bad)); err == nil {
			t.Errorf("decodeSecret(%q) was accepted", bad)
		}
	}
}
