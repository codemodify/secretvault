package svmail

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/codemodify/secretvault/svcms"
)

// S/MIME in mail (RFC 8551): multipart/signed with a detached signature,
// and application/pkcs7-mime holding signed, enveloped or auth-enveloped
// data.

// keysDecrypter lets svcms ask Keys for content keys.
type keysDecrypter struct{ keys Keys }

func (k keysDecrypter) ContentKey(r *svcms.Recipient) ([]byte, error) {
	return k.keys.SMIMEContentKey(r)
}

func (in *inspector) smimeCerts(l *Layer) (roots, inter []*x509.Certificate) {
	roots, err := in.keys.SMIMERoots()
	if err != nil {
		in.warn(WarnKeys, "reading the S/MIME roots: "+err.Error(), l.ID)
	}
	inter, err = in.keys.SMIMEIntermediates()
	if err != nil {
		in.warn(WarnKeys, "reading the S/MIME intermediate certificates: "+err.Error(), l.ID)
	}
	return roots, inter
}

func (in *inspector) verifySMIMEDetached(l *Layer, data, der []byte) {
	sd, err := svcms.ParseSignedData(der, in.lim.cms())
	if err != nil {
		l.Error = "the signature does not parse: " + err.Error()
		in.warn(WarnVerification, fmt.Sprintf("the signature in layer %d could not be read", l.ID), l.ID)
		return
	}
	if sd.Content != nil {
		// Signed content of its own: what it signs is not the part shown
		// beside it, whatever it says.
		l.Error = "the signature part carries signed content of its own, not the part it is attached to"
		in.warn(WarnVerification, fmt.Sprintf("the signature in layer %d is not over the part it signs", l.ID), l.ID)
		return
	}
	in.verifySMIME(l, sd, data)
}

func (in *inspector) verifySMIME(l *Layer, sd *svcms.SignedData, content []byte) {
	roots, inter := in.smimeCerts(l)
	res, err := sd.Verify(svcms.VerifyOptions{Content: content, Roots: roots, Intermediates: inter, Time: in.now})
	if err != nil {
		l.Error = err.Error()
		in.warn(WarnVerification, fmt.Sprintf("the signature in layer %d could not be checked: %v", l.ID, err), l.ID)
		return
	}
	for _, r := range res {
		s := &Signature{Verified: r.Verified, Algorithm: r.Algorithm}
		s.Status, s.Problems = smimeStatus(r)
		if r.Err != nil {
			s.Error = r.Err.Error()
		}
		if !r.SigningTime.IsZero() {
			t := r.SigningTime
			s.SignedAt = &t
		}
		if r.Hash != 0 {
			s.Hash = r.Hash.String()
		}
		cert := r.Certificate
		if cert != nil {
			s.Certificate = describeCert(cert)
			if len(r.Chains) > 0 {
				for _, c := range r.Chains[0][1:] {
					s.Chain = append(s.Chain, describeCert(c))
				}
			}
			if r.Verified {
				in.discover(&DiscoveredKey{Source: "smime-signature", Type: "x509", Certificate: s.Certificate,
					Address: first(svcms.CertificateEmails(cert)), Fingerprint: s.Certificate.SHA256, Data: cert.Raw})
			}
		} else if si := r.Signer; si != nil && si.IssuerAndSerial != nil {
			s.Issuer = si.IssuerAndSerial.IssuerName() + " serial " + strings.ToUpper(si.IssuerAndSerial.Serial.Text(16))
		} else if si != nil {
			s.Issuer = "subject key identifier " + hexUpper(si.SubjectKeyID)
		}
		l.Signatures = append(l.Signatures, s)
		in.sigs = append(in.sigs, sigCheck{layer: l, sig: s, match: func(addr string) bool {
			return cert != nil && svcms.MatchEmail(cert, addr)
		}})
		if s.Status != StatusValid {
			in.warn(WarnVerification, fmt.Sprintf("a signature in layer %d is not valid: %s", l.ID, s.Status), l.ID)
		}
	}
}

// smimeStatus is the most important reason a signature is not valid, and
// every reason.
func smimeStatus(r svcms.SignerResult) (string, []string) {
	var all []string
	if err := r.SignatureErr; err != nil {
		st := StatusError
		switch {
		case errors.Is(err, svcms.ErrBadSignature):
			st = StatusBad
		case errors.Is(err, svcms.ErrUnknownSigner):
			st = StatusUnknownKey
		case errors.Is(err, svcms.ErrWeakAlgorithm):
			st = StatusWeakAlgorithm
		case errors.Is(err, svcms.ErrSignatureMalformed), errors.Is(err, svcms.ErrMalformed):
			st = StatusMalformed
		case errors.Is(err, svcms.ErrUnsupported):
			st = StatusUnsupported
		}
		all = append(all, st)
	}
	if err := r.CertificateErr; err != nil {
		for _, c := range []struct {
			err    error
			status string
		}{
			{svcms.ErrUntrustedRoot, StatusUntrustedRoot},
			{svcms.ErrWrongUsage, StatusWrongUsage},
			{svcms.ErrCertExpired, StatusExpiredKey},
			{svcms.ErrCertInvalid, StatusInvalidKey},
		} {
			if errors.Is(err, c.err) {
				all = append(all, c.status)
			}
		}
		if len(all) == 0 {
			all = append(all, StatusInvalidKey)
		}
	}
	if len(all) == 0 {
		return StatusValid, nil
	}
	return all[0], all
}

// pkcs7Mime reads an application/pkcs7-mime part: opaque signed data, or
// enveloped or auth-enveloped data.
func (in *inspector) pkcs7Mime(p *Part, c walkCtx) {
	der, err := p.Decoded()
	if err != nil {
		in.warn(WarnStructure, where(c)+": the S/MIME part does not decode: "+err.Error(), 0)
		in.leaf(p, c)
		return
	}
	kind := strings.ToLower(p.Params["smime-type"])
	if kind == "" {
		// No smime-type: the CMS content type says.
		oid, err := svcms.ContentType(der, in.lim.cms())
		switch {
		case err != nil:
		case oid.Equal(svcms.OIDSignedData):
			kind = "signed-data"
		case oid.Equal(svcms.OIDEnvelopedData):
			kind = "enveloped-data"
		case oid.Equal(svcms.OIDAuthEnvelopedData):
			kind = "authenveloped-data"
		case oid.Equal(svcms.OIDCompressedData):
			kind = "compressed-data"
		}
	}
	switch kind {
	case "signed-data", "certs-only":
		sd, err := svcms.ParseSignedData(der, in.lim.cms())
		if err != nil {
			in.warn(WarnStructure, where(c)+": the S/MIME signed data does not parse: "+err.Error(), 0)
			in.leaf(p, c)
			return
		}
		if len(sd.Signers) == 0 {
			// Certificates only (RFC 8551, section 3.8).
			for _, cert := range sd.Certificates {
				d := describeCert(cert)
				in.discover(&DiscoveredKey{Source: "smime-certs-only", Type: "x509", Certificate: d, Address: first(svcms.CertificateEmails(cert)), Fingerprint: d.SHA256, Data: cert.Raw})
			}
			in.leaf(p, c)
			return
		}
		l := in.newLayer(KindSignature, FormatSMIMEOpaque, c)
		if l == nil {
			return
		}
		if sd.Content == nil {
			l.Error = "opaque signed data without its content"
			return
		}
		in.verifySMIME(l, sd, sd.Content)
		ic := c.inside(l, true)
		if len(l.Signatures) == 0 {
			ic.signedBy = c.signedBy
		}
		in.readInner(l, ic, sd.Content)
	case "enveloped-data", "authenveloped-data":
		l := in.newLayer(KindEncryption, FormatSMIMEEnveloped, c)
		if l == nil {
			return
		}
		l.Encryption = &Encryption{Recipients: []*Recipient{}}
		ed, err := svcms.ParseEnvelopedData(der, in.lim.cms())
		if err != nil {
			l.Error = "the enveloped data does not parse: " + err.Error()
			in.warn(WarnDecryption, fmt.Sprintf("layer %d could not be read", l.ID), l.ID)
			return
		}
		if ed.Authenticated {
			l.Format = FormatSMIMEAuthEnveloped
		}
		for _, r := range ed.Recipients {
			rr := &Recipient{Algorithm: r.KeyEncryption}
			if r.IssuerAndSerial != nil {
				rr.Issuer = r.IssuerAndSerial.IssuerName()
				rr.Serial = strings.ToUpper(r.IssuerAndSerial.Serial.Text(16))
			} else if r.SubjectKeyID != nil {
				rr.SubjectKeyID = hexUpper(r.SubjectKeyID)
			}
			l.Encryption.Recipients = append(l.Encryption.Recipients, rr)
		}
		l.Encryption.Cipher = ed.ContentEncryption
		pt, err := ed.Decrypt(keysDecrypter{in.keys})
		if err != nil {
			l.Encryption.Error = err.Error()
			in.warn(WarnDecryption, fmt.Sprintf("layer %d was not decrypted: %v", l.ID, err), l.ID)
			return
		}
		defer clear(pt.Content)
		e := l.Encryption
		e.Decrypted = true
		if r := pt.Recipient; r.IssuerAndSerial != nil {
			e.DecryptedWith = r.IssuerAndSerial.IssuerName() + " serial " + strings.ToUpper(r.IssuerAndSerial.Serial.Text(16))
		} else {
			e.DecryptedWith = "subject key identifier " + hexUpper(pt.Recipient.SubjectKeyID)
		}
		e.Cipher = pt.Cipher
		if pt.Authenticated {
			e.Integrity = "aead"
		} else {
			e.Integrity = "none"
			in.warn(WarnNoIntegrity, fmt.Sprintf("layer %d is S/MIME encrypted with %s, which has no integrity protection: anyone could have changed it", l.ID, pt.Cipher), l.ID)
		}
		for _, w := range pt.Warnings {
			in.warn(WarnWeakCipher, fmt.Sprintf("layer %d: %s", l.ID, w), l.ID)
		}
		in.readInner(l, c.inside(l, false), slices.Clone(pt.Content))
	case "compressed-data":
		in.warn(WarnStructure, where(c)+": S/MIME compressed data is not supported", 0)
		in.leaf(p, c)
	default:
		in.warn(WarnStructure, fmt.Sprintf("%s: an S/MIME part of unknown type %q", where(c), kind), 0)
		in.leaf(p, c)
	}
}

// readInner reads the MIME entity inside an opaque signature or an
// encryption layer.
func (in *inspector) readInner(l *Layer, c walkCtx, content []byte) {
	in.setContent(l, c, content)
	inner, err := in.p.entity(content, c.depth, "text/plain")
	if err != nil {
		l.Error = "the content does not parse as a message: " + err.Error()
		return
	}
	in.walk(inner, c)
}

func (in *inspector) discover(k *DiscoveredKey) {
	for _, have := range in.r.Keys {
		if have.Fingerprint == k.Fingerprint && have.Source == k.Source && have.Address == k.Address {
			return
		}
	}
	in.r.Keys = append(in.r.Keys, k)
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func certEmails(c *x509.Certificate) []string { return svcms.CertificateEmails(c) }
