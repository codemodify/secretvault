package svgpgagent

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/codemodify/secretvault/svpgp"
)

// Backend holds the keys and decides who may use them. Serve calls it
// for one connection, from one goroutine.
type Backend interface {
	// Keys lists the keys that can be used now.
	Keys() ([]Key, error)
	// Key returns the key with this keygrip, or ErrNoKey.
	Key(grip []byte) (Key, error)
	// Sign signs a digest with a key, and returns the algorithm's values
	// (svpgp's Key.SignDigest).
	Sign(grip []byte, h svpgp.HashAlgorithm, digest []byte) ([][]byte, error)
	// Decrypt undoes the public-key encryption of data with a key: for
	// RSA it returns the PKCS #1 decoded message (svpgp's
	// Key.DecryptPKCS1), for ECDH the shared point (Key.SharedPoint).
	Decrypt(grip []byte, data []byte) ([]byte, error)
}

// Key is a key the backend holds.
type Key struct {
	Keygrip   []byte
	Algorithm svpgp.PublicKeyAlgorithm
	Public    svpgp.PublicMaterial
	// Confirm says every use of it is confirmed (KEYINFO's 'c' flag).
	Confirm bool
}

// ErrNoKey is a keygrip the backend holds no key for.
var ErrNoKey = &Error{Code: CodeNoSecretKey, Message: "no secret key"}

// Config is what the server says about itself.
type Config struct {
	// Version answers GETINFO version.
	Version string
	// PID answers GETINFO pid.
	PID int
	// Socket and SSHSocket answer GETINFO socket_name and ssh_socket_name
	// ("" when there is none).
	Socket, SSHSocket string
}

// Error is an ERR line: a GnuPG error code (libgpg-error's) and a message
// for people. The source written with it is always gpg-agent's.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Errorf makes an *Error.
func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// GnuPG's error codes (gpg-error.h) that the server and backends answer
// with.
const (
	CodeBadPassphrase  = 11
	CodeNoSecretKey    = 17
	CodeNotFound       = 27
	CodeInvalidValue   = 55
	CodeNoData         = 58
	CodeNotSupported   = 60
	CodeTimeout        = 62
	CodeNotImplemented = 69
	CodeInvalidData    = 79
	CodeInvalidSexp    = 83
	CodeUnsupportedAlg = 84
	CodeNoPinentry     = 85
	CodeNotTrusted     = 98
	CodeCanceled       = 99
	CodeDecryptFailed  = 152
	CodeForbidden      = 251
	CodeFalse          = 256
	codeLineTooLong    = 263
	codeTooMuchData    = 273
	codeUnexpectedCmd  = 274
	codeUnknownCmd     = 275
	codeSyntax         = 276
	codeAssCanceled    = 277
	codeParameter      = 280

	// sourceAgent is GPG_ERR_SOURCE_GPGAGENT, in an error code's top bits.
	sourceAgent = 4 << 24
)

// Limits, as gpg-agent has them.
const (
	maxLine          = 1000 // an Assuan line, without its newline
	maxCiphertext    = 4096 // MAXLEN_CIPHERTEXT
	maxPassphraseLen = 255  // MAX_PASSPHRASE_LEN
)

// session is one connection's state.
type session struct {
	b   Backend
	cfg Config
	r   *bufio.Reader
	w   *bufio.Writer
	raw io.Writer // under w: D lines go straight here, so no copy stays in w

	grip     []byte // SIGKEY or SETKEY
	hash     svpgp.HashAlgorithm
	digest   []byte // SETHASH
	loopback bool   // OPTION pinentry-mode=loopback
}

// Serve speaks gpg-agent's protocol on rw until the client says BYE or
// goes away. It returns nil then, or the error that broke the connection.
func Serve(rw io.ReadWriter, b Backend, cfg Config) error {
	s := &session{b: b, cfg: cfg, r: bufio.NewReaderSize(rw, maxLine+2), w: bufio.NewWriter(rw), raw: rw}
	if err := s.line("OK Pleased to meet you, process " + strconv.Itoa(cfg.PID)); err != nil {
		return err
	}
	for {
		line, err := s.readLine()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, errLineTooLong) {
			// Where the next line starts is not known: say so and stop.
			s.fail(Errorf(codeLineTooLong, "line too long"))
			return err
		}
		if err != nil {
			return err
		}
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		cmd, arg := line, ""
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			cmd, arg = line[:i], line[i+1:]
		}
		if cmd == "" {
			if err := s.fail(Errorf(codeSyntax, "leading white-space")); err != nil {
				return err
			}
			continue
		}
		arg = strings.TrimLeft(arg, " \t")
		cmd = strings.ToUpper(cmd)
		if cmd == "BYE" {
			s.line("OK closing connection")
			return nil
		}
		res, err := s.command(cmd, arg)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) {
				// A broken connection, not an answer.
				return err
			}
			if err := s.fail(e); err != nil {
				return err
			}
			continue
		}
		if err := s.line(strings.TrimRight("OK "+res, " ")); err != nil {
			return err
		}
	}
}

var errLineTooLong = errors.New("svgpgagent: line too long")

// readLine reads one line, without its newline.
func (s *session) readLine() (string, error) {
	b, err := s.r.ReadSlice('\n')
	l := bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
	if errors.Is(err, bufio.ErrBufferFull) || len(l) > maxLine {
		return "", errLineTooLong
	}
	if err != nil {
		if len(b) > 0 && errors.Is(err, io.EOF) {
			return "", io.ErrUnexpectedEOF
		}
		return "", err
	}
	return string(l), nil
}

// line writes one line and flushes.
func (s *session) line(l string) error {
	s.w.WriteString(l)
	s.w.WriteByte('\n')
	return s.w.Flush()
}

// fail writes an ERR line.
func (s *session) fail(e *Error) error {
	msg := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, e.Message)
	if len(msg) > 800 {
		msg = msg[:800]
	}
	return s.line(fmt.Sprintf("ERR %d %s", sourceAgent|e.Code, msg))
}

// status writes an S line.
func (s *session) status(keyword string, args ...string) error {
	return s.line(strings.Join(append([]string{"S", keyword}, args...), " "))
}

// data writes p as D lines, escaped, never splitting an escape. It
// builds each line in one array, writes it past the buffered writer, and
// wipes it, as p may be secret (a session key).
func (s *session) data(p []byte) error {
	if err := s.w.Flush(); err != nil {
		return err
	}
	line := make([]byte, 0, maxLine+1)
	defer func() { clear(line[:cap(line)]) }()
	line = append(line, 'D', ' ')
	for _, c := range p {
		n := 1
		if c == '%' || c == '\r' || c == '\n' || c == '\\' {
			n = 3
		}
		if len(line)+n > maxLine {
			if _, err := s.raw.Write(append(line, '\n')); err != nil {
				return err
			}
			clear(line)
			line = append(line[:0], 'D', ' ')
		}
		if n == 3 {
			line = append(line, '%', "0123456789ABCDEF"[c>>4], "0123456789ABCDEF"[c&15])
		} else {
			line = append(line, c)
		}
	}
	if len(line) > 2 {
		if _, err := s.raw.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// inquire asks the client for data (INQUIRE keyword), reading D lines
// until END. The caller wipes what it gets.
func (s *session) inquire(keyword string, maxLen int) ([]byte, error) {
	if err := s.line("INQUIRE " + keyword); err != nil {
		return nil, err
	}
	var buf []byte
	tooMuch := false
	for {
		// The answer may be secret (a passphrase), so it is read as bytes
		// and wiped where it lay, never made a string.
		line, err := s.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			err = errLineTooLong
		} else if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			clear(line)
			clear(buf)
			return nil, err
		}
		l := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		switch {
		case string(l) == "END":
			if tooMuch {
				return nil, Errorf(codeTooMuchData, "more than %d bytes", maxLen)
			}
			return buf, nil
		case string(l) == "CAN":
			clear(buf)
			return nil, Errorf(codeAssCanceled, "canceled")
		case len(l) > 0 && l[0] == 'D' && (len(l) == 1 || l[1] == ' '):
			if d := l[min(len(l), 2):]; !tooMuch && len(buf)+unescapedLen(d) > maxLen {
				tooMuch = true
				clear(buf)
				buf = nil
			} else if !tooMuch {
				buf = appendUnescaped(buf, d)
			}
			clear(line)
		case len(l) == 0 || l[0] == '#':
		default:
			clear(line)
			clear(buf)
			return nil, Errorf(codeUnexpectedCmd, "only D lines, END or CAN answer an inquiry")
		}
	}
}

// unescapedLen is how long d is once its %XX escapes are decoded.
func unescapedLen(d []byte) int {
	n := 0
	for i := 0; i < len(d); i++ {
		if d[i] == '%' && i+2 < len(d) && isHex(d[i+1]) && isHex(d[i+2]) {
			i += 2
		}
		n++
	}
	return n
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// appendUnescaped decodes d's %XX escapes onto buf, keeping malformed
// ones as they are. An array buf outgrows is wiped.
func appendUnescaped(buf, d []byte) []byte {
	if len(buf)+len(d) > cap(buf) {
		next := make([]byte, len(buf), max(2*cap(buf), len(buf)+len(d), 64))
		copy(next, buf)
		clear(buf)
		buf = next
	}
	for i := 0; i < len(d); i++ {
		if d[i] == '%' && i+2 < len(d) && isHex(d[i+1]) && isHex(d[i+2]) {
			buf = append(buf, unhex(d[i+1])<<4|unhex(d[i+2]))
			i += 2
			continue
		}
		buf = append(buf, d[i])
	}
	return buf
}

// options splits "--a --b=c -- rest" into its options and the rest.
func options(arg string) (map[string]string, string) {
	opts := map[string]string{}
	for {
		arg = strings.TrimLeft(arg, " \t")
		if !strings.HasPrefix(arg, "--") {
			return opts, arg
		}
		word, rest, _ := strings.Cut(arg, " ")
		if word == "--" {
			return opts, strings.TrimLeft(rest, " \t")
		}
		name, value, _ := strings.Cut(word[2:], "=")
		opts[name] = value
		arg = rest
	}
}

// parseGrip reads a keygrip: 40 hex digits.
func parseGrip(s string) ([]byte, error) {
	s, _, _ = strings.Cut(strings.TrimSpace(s), " ")
	grip, err := hex.DecodeString(s)
	if err != nil || len(grip) != 20 {
		return nil, Errorf(codeParameter, "invalid keygrip")
	}
	return grip, nil
}

// asError makes whatever a backend returned an ERR line.
func asError(err error) *Error {
	var e *Error
	switch {
	case errors.As(err, &e):
		return e
	case errors.Is(err, svpgp.ErrDecryption):
		return Errorf(CodeDecryptFailed, "decryption failed")
	case errors.Is(err, svpgp.ErrUnsupported):
		return Errorf(CodeNotSupported, "%s", strings.TrimPrefix(err.Error(), "svpgp: "))
	case errors.Is(err, svpgp.ErrMalformed):
		return Errorf(CodeInvalidData, "%s", strings.TrimPrefix(err.Error(), "svpgp: "))
	case errors.Is(err, svpgp.ErrKeyLocked), errors.Is(err, svpgp.ErrNoUsableKey):
		return Errorf(CodeNoSecretKey, "%s", strings.TrimPrefix(err.Error(), "svpgp: "))
	}
	return Errorf(CodeInvalidValue, "%v", err)
}

// refusals are commands the server knows and will not do, with why.
var refusals = map[string]string{
	"GENKEY":            "secretvault makes keys in the vault: 'secretvault pgp new --v4'",
	"IMPORT_KEY":        "secret keys come into the vault with 'secretvault pgp import', never through gpg",
	"KEYWRAP_KEY":       "secret keys neither come in nor go out this way",
	"EXPORT_KEY":        "the secret key stays in the vault ('secretvault pgp export --secret' takes it out)",
	"DELETE_KEY":        "keys live in vaults: remove the item with 'secretvault rm'",
	"PASSWD":            "the key is protected by its vault: 'secretvault passwd' changes the vault's passphrase",
	"SCD":               "no smartcards here",
	"LEARN":             "no smartcards here",
	"KEYTOCARD":         "no smartcards here",
	"KEYTOTPM":          "no TPM here",
	"KEYATTR":           "keys have no attributes here",
	"PRESET_PASSPHRASE": "nothing is cached",
	"GET_CONFIRMATION":  "secretvault asks people nothing on a program's behalf",
	"MARKTRUSTED":       "secretvault keeps no trust list for gpgsm",
	"GET_SECRET":        "not here",
	"PUT_SECRET":        "not here",
	"GETVAL":            "not here",
	"PUTVAL":            "not here",
	"INPUT":             "no file descriptors are passed here",
	"OUTPUT":            "no file descriptors are passed here",
}

// command runs one command. A nil error is OK, with the text returned.
func (s *session) command(cmd, arg string) (string, error) {
	if why, ok := refusals[cmd]; ok {
		return "", Errorf(CodeNotSupported, "%s", why)
	}
	switch cmd {
	case "NOP", "UPDATESTARTUPTTY", "LISTTRUSTED":
		return "", nil
	case "KILLAGENT", "RELOADAGENT":
		// Other programs share the daemon: it is not a gpg's to stop.
		return "secretvaultd keeps running", nil
	case "RESET":
		s.grip, s.hash, s.digest = nil, 0, nil
		return "", nil
	case "OPTION":
		return "", s.option(arg)
	case "GETINFO":
		return "", s.getinfo(arg)
	case "GETEVENTCOUNTER":
		return "", s.status("EVENTCOUNTER", "0", "0", "0")
	case "HAVEKEY":
		return "", s.haveKey(arg)
	case "KEYINFO":
		return "", s.keyInfo(arg)
	case "READKEY":
		return "", s.readKey(arg)
	case "SIGKEY", "SETKEY":
		grip, err := parseGrip(arg)
		if err != nil {
			return "", err
		}
		s.grip = grip
		return "", nil
	case "SETKEYDESC":
		// gpg describes the key to be unlocked with a passphrase; the
		// daemon's own prompts say what it asks.
		if strings.TrimSpace(arg) == "" {
			return "", Errorf(codeParameter, "no description given")
		}
		return "", nil
	case "SETHASH":
		return "", s.setHash(arg)
	case "PKSIGN":
		return "", s.pksign()
	case "PKDECRYPT":
		return "", s.pkdecrypt()
	case "ISTRUSTED":
		fpr := strings.TrimSpace(arg)
		if _, err := hex.DecodeString(fpr); err != nil || len(fpr) != 40 && len(fpr) != 32 {
			return "", Errorf(codeParameter, "invalid fingerprint")
		}
		return "", Errorf(CodeNotTrusted, "not trusted")
	case "GET_PASSPHRASE":
		return s.getPassphrase(arg)
	case "CLEAR_PASSPHRASE":
		return "", nil // nothing is cached
	case "HELP":
		for _, c := range []string{"NOP", "BYE", "RESET", "OPTION", "GETINFO", "HAVEKEY", "KEYINFO", "READKEY",
			"SIGKEY", "SETKEY", "SETKEYDESC", "SETHASH", "PKSIGN", "PKDECRYPT", "ISTRUSTED", "GET_PASSPHRASE", "CLEAR_PASSPHRASE"} {
			if err := s.line("# " + c); err != nil {
				return "", err
			}
		}
		return "", nil
	case "END", "CANCEL", "AUTH":
		return "", Errorf(CodeNotImplemented, "not implemented")
	case "D":
		return "", Errorf(codeUnexpectedCmd, "data without an inquiry")
	}
	return "", Errorf(codeUnknownCmd, "Unknown IPC command")
}

// option takes "name [=] value", as libassuan does. Every option is
// accepted: they tell gpg-agent about pinentry's display and terminal,
// which secretvault's prompts do not use. pinentry-mode=loopback is
// remembered for GET_PASSPHRASE.
func (s *session) option(arg string) error {
	arg = strings.TrimSpace(arg)
	if arg == "" || arg[0] == '=' {
		return Errorf(codeSyntax, "argument required")
	}
	name, value := arg, ""
	if i := strings.IndexAny(arg, " \t="); i >= 0 {
		name, value = arg[:i], strings.TrimLeft(arg[i:], " \t")
		if strings.HasPrefix(value, "=") {
			value = strings.TrimSpace(value[1:])
			if value == "" {
				return Errorf(codeSyntax, "option argument expected")
			}
		}
	}
	name = strings.TrimPrefix(name, "--")
	if strings.HasPrefix(name, "-") || name == "" {
		return Errorf(codeSyntax, "option should not begin with one dash")
	}
	if name == "pinentry-mode" {
		s.loopback = value == "loopback"
	}
	return nil
}

func (s *session) getinfo(what string) error {
	what = strings.TrimSpace(what)
	answer := func(v string) error {
		if v == "" {
			return Errorf(CodeNoData, "none")
		}
		return s.data([]byte(v))
	}
	switch word, rest, _ := strings.Cut(what, " "); word {
	case "version":
		return answer(s.cfg.Version)
	case "pid":
		return answer(strconv.Itoa(s.cfg.PID))
	case "socket_name":
		return answer(s.cfg.Socket)
	case "ssh_socket_name":
		return answer(s.cfg.SSHSocket)
	case "s2k_count":
		// For what gpg protects symmetrically itself: the most the S2K
		// count can say.
		return answer("65011712")
	case "cmd_has_option":
		c, o, _ := strings.Cut(strings.TrimSpace(rest), " ")
		o = strings.TrimSpace(o)
		if c == "" || o == "" {
			return Errorf(CodeInvalidValue, "a command and an option")
		}
		if strings.EqualFold(c, "GET_PASSPHRASE") && (o == "repeat" || o == "data" || o == "no-ask") {
			return nil
		}
		return Errorf(CodeFalse, "no")
	case "restricted", "ephemeral", "scd_running", "jent_active":
		return Errorf(CodeFalse, "no")
	case "getenv", "std_env_names", "std_session_env", "std_startup_env", "connections":
		return Errorf(CodeNotSupported, "not here")
	}
	return Errorf(codeParameter, "unknown value for WHAT")
}

// haveKey is HAVEKEY GRIP..., HAVEKEY --list[=N] and HAVEKEY --info GRIP.
func (s *session) haveKey(arg string) error {
	opts, rest := options(arg)
	if n, ok := opts["list"]; ok {
		limit := -1
		if n != "" {
			if v, err := strconv.Atoi(n); err == nil && v > 0 {
				limit = v
			}
		}
		keys, err := s.b.Keys()
		if err != nil {
			return asError(err)
		}
		if limit >= 0 && len(keys) > limit {
			return Errorf(154, "more than %d keys", limit) // GPG_ERR_TRUNCATED
		}
		var all []byte
		for _, k := range keys {
			all = append(all, k.Keygrip...)
		}
		if len(all) == 0 {
			return nil
		}
		return s.data(all)
	}
	if _, ok := opts["info"]; ok {
		grip, err := parseGrip(rest)
		if err != nil {
			return err
		}
		if _, err := s.b.Key(grip); err != nil {
			return asError(err)
		}
		return s.status("KEYFILEINFO", "unknown")
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return Errorf(codeParameter, "invalid keygrip")
	}
	var grips [][]byte
	for _, f := range fields {
		grip, err := parseGrip(f)
		if err != nil {
			return err
		}
		grips = append(grips, grip)
	}
	for _, grip := range grips {
		if _, err := s.b.Key(grip); err == nil {
			return nil
		} else if e := asError(err); e.Code != CodeNoSecretKey {
			return e
		}
	}
	return Errorf(CodeNoSecretKey, "no secret key")
}

// keyInfo is KEYINFO [--list] [--data] ... GRIP. The line gpg reads:
// keygrip, type (D: a key the agent holds), serial number, ID string,
// cached, protection, SSH fingerprint, TTL and flags.
func (s *session) keyInfo(arg string) error {
	opts, rest := options(arg)
	_, withData := opts["data"]
	_, needAttr := opts["need-attr"]
	describe := func(k Key) error {
		flags := "-"
		if k.Confirm {
			flags = "c"
		}
		fields := []string{strings.ToUpper(hex.EncodeToString(k.Keygrip)), "D", "-", "-", "-", "-", "-", "-", flags}
		if withData {
			return s.data([]byte(strings.Join(fields, " ") + "\n"))
		}
		return s.status("KEYINFO", fields...)
	}
	if _, ok := opts["ssh-list"]; ok {
		return nil // no key here is listed for ssh
	}
	if _, ok := opts["list"]; ok {
		if needAttr {
			return nil // no key here has attributes
		}
		keys, err := s.b.Keys()
		if err != nil {
			return asError(err)
		}
		for _, k := range keys {
			if err := describe(k); err != nil {
				return err
			}
		}
		return nil
	}
	grip, err := parseGrip(rest)
	if err != nil {
		return err
	}
	k, err := s.b.Key(grip)
	if err != nil {
		if e := asError(err); e.Code != CodeNoSecretKey {
			return e
		}
		return Errorf(CodeNotFound, "not found")
	}
	if needAttr {
		return Errorf(CodeNotFound, "not found")
	}
	return describe(k)
}

// readKey is READKEY [--no-data] GRIP: the public key.
func (s *session) readKey(arg string) error {
	opts, rest := options(arg)
	if _, ok := opts["card"]; ok {
		return Errorf(CodeNotSupported, "no smartcards here")
	}
	if f, ok := opts["format"]; ok && f != "" {
		return Errorf(CodeNotSupported, "only the S-expression form")
	}
	grip, err := parseGrip(rest)
	if err != nil {
		return err
	}
	k, err := s.b.Key(grip)
	if err != nil {
		return asError(err)
	}
	pub, err := publicKey(k.Algorithm, k.Public)
	if err != nil {
		return asError(err)
	}
	if _, ok := opts["no-data"]; ok {
		return nil
	}
	return s.data(pub)
}

// Hash algorithms by libgcrypt's number (gcrypt.h), and SETHASH's names.
var mdAlgos = map[int]svpgp.HashAlgorithm{
	1: svpgp.MD5, 2: svpgp.SHA1, 3: svpgp.RIPEMD160, 8: svpgp.SHA256, 9: svpgp.SHA384,
	10: svpgp.SHA512, 11: svpgp.SHA224, 313: svpgp.SHA3_256, 315: svpgp.SHA3_512,
}

var mdNames = map[string]int{"md5": 1, "sha1": 2, "rmd160": 3, "sha256": 8, "sha384": 9, "sha512": 10, "sha224": 11}

// setHash is SETHASH ALGO HEX, or SETHASH --hash=NAME HEX.
func (s *session) setHash(arg string) error {
	opts, rest := options(arg)
	if _, ok := opts["inquire"]; ok {
		return Errorf(CodeNotSupported, "only a digest is signed here, not data (PureEdDSA)")
	}
	if _, ok := opts["pss"]; ok {
		return Errorf(CodeNotSupported, "RSA-PSS is not made here")
	}
	var algo int
	if name, ok := opts["hash"]; ok {
		if algo, ok = mdNames[name]; !ok {
			return Errorf(codeParameter, "invalid hash algorithm")
		}
	} else {
		n, r, _ := strings.Cut(rest, " ")
		v, err := strconv.Atoi(n)
		if err != nil {
			return Errorf(CodeUnsupportedAlg, "unsupported algorithm")
		}
		algo, rest = v, r
	}
	h, ok := mdAlgos[algo]
	if !ok {
		return Errorf(CodeUnsupportedAlg, "unsupported algorithm")
	}
	hexDigest, _, _ := strings.Cut(strings.TrimSpace(rest), " ")
	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return Errorf(codeParameter, "invalid hexstring")
	}
	switch len(digest) {
	case 16, 20, 24, 28, 32, 48, 64:
	default:
		return Errorf(codeParameter, "unsupported length of hash")
	}
	s.hash, s.digest = h, digest
	return nil
}

// pksign signs the SETHASH digest with the SIGKEY key, and answers with
// the signature: (sig-val(rsa(s S))), (sig-val(ecdsa(r R)(s S))) or
// (sig-val(eddsa(r R)(s S))).
func (s *session) pksign() error {
	if s.grip == nil {
		return Errorf(CodeNoSecretKey, "no key given (SIGKEY)")
	}
	if s.digest == nil {
		return Errorf(CodeNoData, "no digest given (SETHASH)")
	}
	if s.hash.Size() != len(s.digest) {
		return Errorf(CodeInvalidValue, "a %v digest is %d bytes, not %d", s.hash, s.hash.Size(), len(s.digest))
	}
	k, err := s.b.Key(s.grip)
	if err != nil {
		return asError(err)
	}
	var name string
	switch k.Algorithm {
	case svpgp.RSA, svpgp.RSASignOnly:
		name = "rsa"
	case svpgp.ECDSA:
		name = "ecdsa"
	case svpgp.EdDSALegacy, svpgp.Ed25519:
		name = "eddsa"
	default:
		return Errorf(CodeNotSupported, "%v keys do not sign", k.Algorithm)
	}
	values, err := s.b.Sign(s.grip, s.hash, s.digest)
	if err != nil {
		return asError(err)
	}
	elems := [][]byte{atom([]byte(name))}
	switch name {
	case "rsa":
		if len(values) != 1 {
			return Errorf(CodeInvalidValue, "a signature of %d values", len(values))
		}
		elems = append(elems, param("s", mpi(values[0])))
	case "ecdsa":
		if len(values) != 2 {
			return Errorf(CodeInvalidValue, "a signature of %d values", len(values))
		}
		elems = append(elems, param("r", mpi(values[0])), param("s", mpi(values[1])))
	case "eddsa":
		if len(values) != 2 {
			return Errorf(CodeInvalidValue, "a signature of %d values", len(values))
		}
		elems = append(elems, param("r", values[0]), param("s", values[1]))
	}
	return s.data(list(atom([]byte("sig-val")), list(elems...)))
}

// pkdecrypt asks for the ciphertext, (enc-val(rsa(a A))) or
// (enc-val(ecdh(s S)(e E))), and answers with (value V): for RSA the
// session key, after a PADDING 0 status saying the padding is gone; for
// ECDH the shared point.
func (s *session) pkdecrypt() error {
	if err := s.status("INQUIRE_MAXLEN", strconv.Itoa(maxCiphertext)); err != nil {
		return err
	}
	ct, err := s.inquire("CIPHERTEXT", maxCiphertext)
	if err != nil {
		return err
	}
	if s.grip == nil {
		return Errorf(CodeNoSecretKey, "no key given (SETKEY)")
	}
	e, err := parseSexp(ct)
	if err != nil || e.name() != "enc-val" {
		return Errorf(CodeInvalidSexp, "the ciphertext is not an enc-val S-expression")
	}
	var alg *sexp
	for _, c := range e.list[1:] {
		switch c.name() {
		case "flags":
			for _, f := range c.list[1:] {
				if f.isList || string(f.atom) != "pkcs1" {
					return Errorf(CodeNotSupported, "the flag %q", f.atom)
				}
			}
		case "rsa", "ecdh", "elg":
			if alg != nil {
				return Errorf(CodeInvalidSexp, "two algorithms")
			}
			alg = c
		default:
			return Errorf(CodeInvalidSexp, "unexpected %q", c.name())
		}
	}
	if alg == nil {
		return Errorf(CodeInvalidSexp, "no algorithm")
	}
	k, err := s.b.Key(s.grip)
	if err != nil {
		return asError(err)
	}
	var data []byte
	var ok bool
	switch alg.name() {
	case "rsa":
		if k.Algorithm != svpgp.RSA && k.Algorithm != svpgp.RSAEncryptOnly {
			return Errorf(CodeNotSupported, "an RSA ciphertext for a %v key", k.Algorithm)
		}
		data, ok = alg.find("a").value()
	case "ecdh":
		if k.Algorithm != svpgp.ECDH && k.Algorithm != svpgp.X25519 {
			return Errorf(CodeNotSupported, "an ECDH ciphertext for a %v key", k.Algorithm)
		}
		data, ok = alg.find("e").value()
	default:
		return Errorf(CodeNotSupported, "ElGamal is not decrypted here")
	}
	if !ok || len(data) == 0 {
		return Errorf(CodeInvalidSexp, "the ciphertext's value is missing")
	}
	value, err := s.b.Decrypt(s.grip, data)
	if err != nil {
		return asError(err)
	}
	defer clear(value)
	if alg.name() == "rsa" {
		if err := s.status("PADDING", "0"); err != nil {
			return err
		}
	} else if isCurve25519(k.Algorithm, k.Public) {
		value = append([]byte{0x40}, value...)
	}
	out := param("value", value)
	defer clear(out)
	return s.data(out)
}

// getPassphrase is GET_PASSPHRASE. secretvault never asks a person for a
// passphrase on a program's behalf: what the person typed would go to
// the program, from a prompt that looks like secretvault's own. With
// pinentry-mode=loopback, gpg answers for itself (from --passphrase, or
// its own terminal), and the passphrase only goes back to it.
func (s *session) getPassphrase(arg string) (string, error) {
	opts, rest := options(arg)
	if strings.TrimSpace(rest) == "" {
		return "", Errorf(codeParameter, "no cache ID given")
	}
	if _, ok := opts["no-ask"]; ok {
		return "", Errorf(CodeNoData, "nothing is cached")
	}
	if !s.loopback {
		return "", Errorf(CodeNoPinentry, "secretvault asks for no passphrase on a program's behalf; use gpg's --pinentry-mode loopback")
	}
	if err := s.status("INQUIRE_MAXLEN", strconv.Itoa(maxPassphraseLen)); err != nil {
		return "", err
	}
	pass, err := s.inquire("PASSPHRASE", maxPassphraseLen)
	if err != nil {
		return "", err
	}
	defer clear(pass)
	if _, ok := opts["data"]; ok {
		return "", s.data(pass)
	}
	// Without --data, the answer is the OK line, in hex.
	if len(pass) == 0 {
		return "", Errorf(CodeNoData, "no passphrase given")
	}
	return strings.ToUpper(hex.EncodeToString(pass)), nil
}
