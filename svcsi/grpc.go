package svcsi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Just enough gRPC (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
// for the driver's two unary calls, on the standard library: HTTP/2 in
// the clear with prior knowledge (as gRPC speaks over a unix socket),
// served by net/http. A call is a POST to /PACKAGE.SERVICE/METHOD with
// content-type application/grpc; the request and the response are each
// one length-prefixed message:
//
//	compressed flag (1 byte, 0: we support no compression)
//	length (4 bytes, big-endian)
//	the message, in protobuf
//
// and the outcome is in the trailers: grpc-status (a code, 0 for OK) and
// grpc-message (percent-encoded).

// gRPC status codes.
const (
	codeOK               = 0
	codeInvalidArgument  = 3
	codeNotFound         = 5
	codePermissionDenied = 7
	codeInternal         = 13
	codeUnimplemented    = 12
	codeUnavailable      = 14
	codeUnauthenticated  = 16
)

// maxMessage caps a request message. A MountRequest carries the pod's
// attributes and the secret's data: kilobytes.
const maxMessage = 4 << 20

// statusError is a call that failed with a gRPC status.
type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return e.msg }

func statusf(code int, format string, args ...any) error {
	return &statusError{code: code, msg: fmt.Sprintf(format, args...)}
}

// method is a unary method: it gets the request message and returns the
// response's.
type method func(ctx context.Context, req []byte) ([]byte, error)

// grpcServer answers unary gRPC calls.
type grpcServer struct {
	methods map[string]method // by path: /v1alpha1.CSIDriverProvider/Mount
}

func (g *grpcServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if r.Method != http.MethodPost || !(ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+proto") || strings.HasPrefix(ct, "application/grpc;")) {
		http.Error(w, "this socket speaks gRPC only", http.StatusUnsupportedMediaType)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	h.Set("Trailer", "Grpc-Status, Grpc-Message")
	m := g.methods[r.URL.Path]
	if m == nil {
		finish(w, statusf(codeUnimplemented, "there is no method %s", r.URL.Path))
		return
	}
	req, err := readMessage(r.Body)
	if err != nil {
		finish(w, err)
		return
	}
	resp, err := m(r.Context(), req)
	if err != nil {
		finish(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	var head [5]byte
	binary.BigEndian.PutUint32(head[1:], uint32(len(resp)))
	w.Write(head[:])
	w.Write(resp)
	finish(w, nil)
}

// readMessage reads the one message of a unary call.
func readMessage(r io.Reader) ([]byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, statusf(codeInvalidArgument, "the request holds no message")
	}
	if head[0] != 0 {
		return nil, statusf(codeUnimplemented, "compressed messages are not supported")
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > maxMessage {
		return nil, statusf(codeInvalidArgument, "the request message is larger than %d bytes", maxMessage)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, statusf(codeInvalidArgument, "the request message is cut short")
	}
	if extra, _ := io.ReadFull(r, head[:1]); extra != 0 {
		return nil, statusf(codeInvalidArgument, "a unary call takes one message")
	}
	return msg, nil
}

// finish sets the trailers: OK, or the error's status.
func finish(w http.ResponseWriter, err error) {
	code, msg := codeOK, ""
	if err != nil {
		var se *statusError
		if errors.As(err, &se) {
			code, msg = se.code, se.msg
		} else {
			code, msg = codeInternal, err.Error()
		}
	}
	h := w.Header()
	h.Set("Grpc-Status", strconv.Itoa(code))
	if msg != "" {
		h.Set("Grpc-Message", percentEncode(msg))
	}
}

// percentEncode writes a grpc-message: bytes outside printable ASCII, and
// '%', as %XX.
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// serveUnix serves h over HTTP/2 in the clear on a unix socket at path,
// until ctx ends. A socket left by an earlier run is replaced.
func serveUnix(ctx context.Context, path string, h http.Handler) error {
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	// Only root (the driver) and this user may connect.
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return err
	}
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: h, Protocols: &p, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(stop)
		os.Remove(path)
		return nil
	}
}
