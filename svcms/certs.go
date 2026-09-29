package svcms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Usage is what a certificate is being checked for.
type Usage int

const (
	// UsageSigning is signing messages: the key usage, if present, must
	// allow digitalSignature or nonRepudiation.
	UsageSigning Usage = iota
	// UsageEncryption is receiving encrypted messages: the key usage, if
	// present, must allow keyEncipherment for an RSA key and keyAgreement
	// for an EC key.
	UsageEncryption
)

// CertOptions say what a certificate is checked against.
type CertOptions struct {
	// Roots are the trusted roots. With none, no certificate is trusted:
	// the operating system's roots are never used implicitly.
	Roots []*x509.Certificate
	// Intermediates may be used to build chains.
	Intermediates []*x509.Certificate
	// Time is when the certificate must be valid; zero means now.
	Time time.Time
	// Email, if set, must be one of the certificate's addresses.
	Email string
	// Usage is what the certificate is for.
	Usage Usage
}

// VerifyCertificate checks an S/MIME certificate: that it chains to one of
// the roots (x509 path validation, with the emailProtection extended key
// usage through the chain), is valid at the time, has a key usage that
// allows the use, and, if an address is given, names it. It returns the
// chains it built, even when it reports a problem, and every problem it
// found, joined: test for ErrUntrustedRoot, ErrCertExpired, ErrWrongUsage,
// ErrAddressMismatch and ErrCertInvalid with errors.Is.
func VerifyCertificate(cert *x509.Certificate, opts CertOptions) ([][]*x509.Certificate, error) {
	t := opts.Time
	if t.IsZero() {
		t = time.Now()
	}
	var errs []error
	if !emailProtection(cert) {
		errs = append(errs, fmt.Errorf("%w: its extended key usage does not include emailProtection", ErrWrongUsage))
	}
	if err := keyUsageAllows(cert, opts.Usage); err != nil {
		errs = append(errs, err)
	}
	// Chains are built at a time the certificate itself was valid, so an
	// expired certificate is reported as expired and, separately, as
	// trusted or not.
	at := t
	switch {
	case t.Before(cert.NotBefore):
		errs = append(errs, fmt.Errorf("%w: not valid until %s", ErrCertExpired, cert.NotBefore.UTC().Format(time.RFC3339)))
		at = cert.NotBefore
	case t.After(cert.NotAfter):
		errs = append(errs, fmt.Errorf("%w: expired %s", ErrCertExpired, cert.NotAfter.UTC().Format(time.RFC3339)))
		at = cert.NotAfter
	}
	roots := x509.NewCertPool()
	for _, r := range opts.Roots {
		roots.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, c := range opts.Intermediates {
		inter.AddCert(c)
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	})
	if err != nil {
		if e := classifyChainError(err, errs); e != nil {
			errs = append(errs, e)
		}
	}
	var good [][]*x509.Certificate
	var constraintErr error
	for _, chain := range chains {
		if err := emailConstraints(cert, chain); err != nil {
			constraintErr = err
			continue
		}
		good = append(good, chain)
	}
	if len(chains) > 0 && len(good) == 0 {
		errs = append(errs, constraintErr)
	}
	chains = good
	if opts.Email != "" && !MatchEmail(cert, opts.Email) {
		errs = append(errs, fmt.Errorf("%w: %s is not among %s", ErrAddressMismatch, opts.Email, strings.Join(CertificateEmails(cert), ", ")))
	}
	return chains, errors.Join(errs...)
}

// classifyChainError maps crypto/x509's verification errors onto this
// package's, or returns nil for one already reported.
func classifyChainError(err error, already []error) error {
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return fmt.Errorf("%w: %v", ErrUntrustedRoot, err)
	case errors.As(err, &ci):
		switch ci.Reason {
		case x509.Expired:
			return fmt.Errorf("%w: an issuer: %v", ErrCertExpired, err)
		case x509.IncompatibleUsage:
			for _, e := range already {
				if errors.Is(e, ErrWrongUsage) {
					return nil
				}
			}
			return fmt.Errorf("%w: an issuer does not allow emailProtection: %v", ErrWrongUsage, err)
		}
	}
	return fmt.Errorf("%w: %v", ErrCertInvalid, err)
}

// emailProtection says whether the extended key usage allows S/MIME: it is
// absent, or lists emailProtection or anyExtendedKeyUsage (RFC 8550,
// section 4.4.4).
func emailProtection(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	return slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageEmailProtection) ||
		slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny)
}

// keyUsageAllows checks the key usage extension, if present (RFC 8550,
// section 4.4.2).
func keyUsageAllows(cert *x509.Certificate, u Usage) error {
	ku := cert.KeyUsage
	if ku == 0 {
		return nil
	}
	switch u {
	case UsageSigning:
		if ku&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
			return fmt.Errorf("%w: its key usage does not allow digitalSignature or nonRepudiation", ErrWrongUsage)
		}
	case UsageEncryption:
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if ku&x509.KeyUsageKeyEncipherment == 0 {
				return fmt.Errorf("%w: its key usage does not allow keyEncipherment", ErrWrongUsage)
			}
		case *ecdsa.PublicKey:
			if ku&x509.KeyUsageKeyAgreement == 0 {
				return fmt.Errorf("%w: its key usage does not allow keyAgreement", ErrWrongUsage)
			}
		case ed25519.PublicKey:
			return fmt.Errorf("%w: an Ed25519 key cannot receive encrypted messages", ErrWrongUsage)
		}
	}
	return nil
}

// CertificateEmails are the addresses a certificate names: its
// rfc822Name subject alternative names or, only when it has none, any
// emailAddress in its subject (the legacy form, RFC 8550, section 3;
// RFC 5280, section 4.2.1.6).
func CertificateEmails(cert *x509.Certificate) []string {
	if len(cert.EmailAddresses) > 0 {
		return slices.Clone(cert.EmailAddresses)
	}
	return subjectEmails(cert)
}

func subjectEmails(cert *x509.Certificate) []string {
	var out []string
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(oidEmailAddress) {
			if s, ok := atv.Value.(string); ok && !slices.ContainsFunc(out, func(e string) bool { return strings.EqualFold(e, s) }) {
				out = append(out, s)
			}
		}
	}
	return out
}

// emailConstraints applies the rfc822Name constraints of a chain's CAs to
// a leaf's subject emailAddress when it has no rfc822Name to carry them,
// as RFC 5280 (section 4.2.1.10) requires and crypto/x509 does not.
func emailConstraints(cert *x509.Certificate, chain []*x509.Certificate) error {
	if len(cert.EmailAddresses) > 0 {
		return nil
	}
	for _, addr := range subjectEmails(cert) {
		for _, ca := range chain[1:] {
			if len(ca.PermittedEmailAddresses) > 0 && !slices.ContainsFunc(ca.PermittedEmailAddresses, func(c string) bool { return emailMatchesConstraint(addr, c) }) {
				return fmt.Errorf("%w: %s is outside the addresses %s may certify", ErrCertInvalid, addr, ca.Subject)
			}
			if slices.ContainsFunc(ca.ExcludedEmailAddresses, func(c string) bool { return emailMatchesConstraint(addr, c) }) {
				return fmt.Errorf("%w: %s is among the addresses %s may not certify", ErrCertInvalid, addr, ca.Subject)
			}
		}
	}
	return nil
}

// emailMatchesConstraint matches an address against an rfc822Name
// constraint: a mailbox, a host, or (with a leading dot) any host in a
// domain.
func emailMatchesConstraint(addr, constraint string) bool {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return false
	}
	host := strings.ToLower(addr[at+1:])
	c := strings.ToLower(constraint)
	switch {
	case strings.Contains(c, "@"):
		return strings.EqualFold(addr, constraint)
	case strings.HasPrefix(c, "."):
		return strings.HasSuffix(host, c)
	}
	return host == c
}

// MatchEmail says whether the certificate names the address. The
// comparison ignores case in the whole address, as mail clients do.
func MatchEmail(cert *x509.Certificate, addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	for _, e := range CertificateEmails(cert) {
		if strings.EqualFold(strings.TrimSpace(e), addr) {
			return true
		}
	}
	return false
}
