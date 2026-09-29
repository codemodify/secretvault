// Command secretvault-server is secretvault's own sync server: it keeps
// the files of vaults and relays them between each vault's devices, and
// only ever sees ciphertext (see svserver and docs/security.md).
//
//   - Devices sign every request with their own Ed25519 key. A device
//     makes a vault on the server with the admin token (or freely, with
//     -open-registration), and enrols others with one-time codes.
//
//   - It serves HTTPS with a certificate you give it (-tls-cert, -tls-key),
//     or with a self-signed one it makes and keeps under the root
//     (-self-signed), whose SHA-256 fingerprint it prints for devices to
//     pin. Behind a reverse proxy that terminates TLS, -insecure-http
//     serves plain HTTP instead.
//
//   - Everything lives under -root: the vaults' files, their change logs
//     and enrolled devices, and the self-signed certificate. One server
//     process owns a root at a time.
//
// Usage:
//
//	secretvault-server -self-signed -admin-token-file /etc/secretvault/admin-token
//	secretvault-server -tls-cert cert.pem -tls-key key.pem -open-registration
//	secretvault-server -insecure-http -listen 127.0.0.1:8080   (behind a proxy)
//	secretvault-server -version
//
// It stops cleanly on SIGINT or SIGTERM.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svserver"
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("secretvault-server: ")
	var (
		listen       = flag.String("listen", ":8443", "address to listen on")
		root         = flag.String("root", "", "directory to keep everything in (default: <secretvault home>/server)")
		certFile     = flag.String("tls-cert", "", "TLS certificate (PEM)")
		keyFile      = flag.String("tls-key", "", "TLS private key (PEM)")
		selfSigned   = flag.Bool("self-signed", false, "make (once) and use a self-signed certificate kept under the root")
		hostnames    = flag.String("hostname", "", "comma-separated names and addresses for the self-signed certificate (default: this host's name and localhost)")
		plain        = flag.Bool("insecure-http", false, "serve plain HTTP, for running behind a reverse proxy that terminates TLS")
		tokenFile    = flag.String("admin-token-file", "", "file holding the admin token that lets a device make a vault")
		open         = flag.Bool("open-registration", false, "let any device make a vault, without the admin token")
		maxFile      = flag.Int64("max-file-size", svserver.DefaultMaxRevision, "largest revision accepted, in bytes")
		rate         = flag.Float64("rate", 0, "requests a second allowed per device and per IP address (0: 100; negative: no limit)")
		printVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *printVersion {
		fmt.Println("secretvault-server", secretvault.Version)
		return
	}
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	modes := 0
	for _, on := range []bool{*certFile != "" || *keyFile != "", *selfSigned, *plain} {
		if on {
			modes++
		}
	}
	if modes != 1 || (*certFile == "") != (*keyFile == "") {
		log.Fatal("choose one of: -tls-cert with -tls-key, -self-signed, or -insecure-http")
	}
	if *root == "" {
		home, err := svcore.Home()
		if err != nil {
			log.Fatal(err)
		}
		*root = filepath.Join(home, "server")
	}
	if err := os.MkdirAll(*root, 0o700); err != nil {
		log.Fatal(err)
	}

	var token string
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatal(err)
		}
		token = strings.TrimSpace(string(b))
		if len(token) < 16 {
			log.Fatalf("the admin token in %s is shorter than 16 characters", *tokenFile)
		}
	}
	if token == "" && !*open {
		log.Print("no device can make a vault here: pass -admin-token-file or -open-registration (existing vaults still sync)")
	}

	var cert *tls.Certificate
	switch {
	case *selfSigned:
		hosts := splitList(*hostnames)
		if len(hosts) == 0 {
			if h, err := os.Hostname(); err == nil {
				hosts = append(hosts, h)
			}
			hosts = append(hosts, "localhost", "127.0.0.1", "::1")
		}
		c, err := svserver.SelfSigned(filepath.Join(*root, "tls"), hosts)
		if err != nil {
			log.Fatal(err)
		}
		cert = &c
	case *certFile != "":
		c, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatal(err)
		}
		cert = &c
	}

	srv, err := svserver.New(svserver.Config{
		Root:             *root,
		AdminToken:       token,
		OpenRegistration: *open,
		MaxFileSize:      *maxFile,
		Rate:             *rate,
		Log:              func(s string) { log.Print(s) },
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		srv.Close() // ends long polls, so the HTTP server can stop
	}()

	scheme := "https"
	if cert == nil {
		scheme = "http"
	} else {
		log.Printf("certificate fingerprint (SHA-256; devices pin it): %s", svserver.Fingerprint(cert.Certificate[0]))
	}
	reg := "by admin token"
	switch {
	case *open:
		reg = "open to any device"
	case token == "":
		reg = "closed"
	}
	log.Printf("%s serving %s://%s, keeping vaults in %s; making vaults is %s", secretvault.Version, scheme, *listen, *root, reg)
	if err := svserver.ListenAndServe(ctx, *listen, srv, cert); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
	log.Print("stopped")
}

func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
