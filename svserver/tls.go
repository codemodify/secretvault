package svserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Fingerprint is how a device pins a server's certificate: the SHA-256 of
// the certificate's DER bytes, in lowercase hex.
func Fingerprint(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// Names of the self-signed certificate's files.
const (
	CertFile = "cert.pem"
	KeyFile  = "key.pem"
)

// SelfSigned returns the certificate kept in dir, making a self-signed one
// (ECDSA P-256, valid for ten years) for hosts the first time. Devices
// trust it by its Fingerprint rather than through any authority.
func SelfSigned(dir string, hosts []string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return cert, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "secretvault sync server"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	// The key goes first: a certificate without its key is never left
	// behind looking usable.
	if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// ListenAndServe serves h on addr until ctx ends: over TLS (1.2 and up)
// with cert, or as plain HTTP when cert is nil, for running behind a
// reverse proxy that terminates TLS. Timeouts leave room for a long poll
// (MaxWait) and for large revisions on slow links. Close the Server first
// (or as ctx ends) so long polls do not hold up the shutdown.
func ListenAndServe(ctx context.Context, addr string, h http.Handler, cert *tls.Certificate) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() {
		if cert != nil {
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
			errc <- srv.ServeTLS(ln, "", "")
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(stop); err != nil {
			srv.Close()
		}
		return nil
	}
}
