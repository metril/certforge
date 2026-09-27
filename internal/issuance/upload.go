package issuance

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/signer"
)

// UploadInput is the raw material behind an uploaded certificate or version
// (R10): a PEM leaf, optionally followed by its chain, plus an optional PEM
// private key, or a PKCS#12 bundle with its password. Exactly one of
// CertificatePEM or PKCS12 is set.
type UploadInput struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	PKCS12         []byte
	Password       string
}

// ParseUpload decodes in into canonical Issued material and its key type,
// validating shape only (no database access, so it is reused as-is by
// Task 14's importer and is fully unit-testable).
//
// PEM: the first CERTIFICATE block is the leaf, every block after it is the
// chain, in order. PKCS#12: pkcs12.DecodeChain. A supplied key (PEM, or
// embedded in the PKCS#12 bundle) must match the leaf's public key, or this
// is a 422 on privateKeyPem. Key encodings PKCS#1, SEC1 and PKCS#8 are all
// accepted and normalised to PKCS#8; omitting the key (both PrivateKeyPEM
// and any PKCS#12 key) stores a keyless version. KeyTypeOf classifies the
// leaf's own public key either way (so a keyless upload is still typed);
// anything it rejects (ed25519, an unusual RSA size or EC curve) is 422
// too.
func ParseUpload(in UploadInput) (*signer.Issued, signer.KeyType, error) {
	switch {
	case len(in.CertificatePEM) > 0 && len(in.PKCS12) > 0:
		return nil, "", &ValidationError{"certificatePem", "exactly one of certificatePem or pkcs12Base64 is allowed"}
	case len(in.CertificatePEM) == 0 && len(in.PKCS12) == 0:
		return nil, "", &ValidationError{"certificatePem", "certificatePem or pkcs12Base64 is required"}
	}

	var leafDER []byte
	var chainDER [][]byte
	var keyDER []byte // PKCS#8, or nil for a keyless upload

	if len(in.CertificatePEM) > 0 {
		var ders [][]byte
		rest := in.CertificatePEM
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type == "CERTIFICATE" {
				ders = append(ders, b.Bytes)
			}
		}
		if len(ders) == 0 {
			return nil, "", &ValidationError{"certificatePem", "no certificate found"}
		}
		leafDER, chainDER = ders[0], ders[1:]
		if len(in.PrivateKeyPEM) > 0 {
			var err error
			if keyDER, err = normalizeKeyPEM(in.PrivateKeyPEM); err != nil {
				return nil, "", &ValidationError{"privateKeyPem", err.Error()}
			}
		}
	} else {
		key, cert, caCerts, err := pkcs12.DecodeChain(in.PKCS12, in.Password)
		if err != nil {
			return nil, "", &ValidationError{"pkcs12Base64", "cannot decode: " + err.Error()}
		}
		leafDER = cert.Raw
		for _, c := range caCerts {
			chainDER = append(chainDER, c.Raw)
		}
		if key != nil {
			signerKey, ok := key.(crypto.Signer)
			if !ok {
				return nil, "", &ValidationError{"pkcs12Base64", fmt.Sprintf("unsupported key type %T", key)}
			}
			if keyDER, err = x509.MarshalPKCS8PrivateKey(signerKey); err != nil {
				return nil, "", &ValidationError{"pkcs12Base64", "cannot marshal key: " + err.Error()}
			}
		}
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, "", &ValidationError{"certificatePem", "cannot parse leaf: " + err.Error()}
	}

	keyField := "certificatePem"
	if keyDER != nil {
		keyField = "privateKeyPem"
		key, err := x509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			return nil, "", &ValidationError{"privateKeyPem", "cannot parse key: " + err.Error()}
		}
		signerKey, ok := key.(crypto.Signer)
		if !ok {
			return nil, "", &ValidationError{"privateKeyPem", fmt.Sprintf("unsupported key type %T", key)}
		}
		if !publicKeysEqual(leaf.PublicKey, signerKey.Public()) {
			return nil, "", &ValidationError{"privateKeyPem", "does not match the certificate"}
		}
	}
	keyType, err := signer.KeyTypeOf(leaf.PublicKey)
	if err != nil {
		return nil, "", &ValidationError{keyField, err.Error()}
	}

	if chainDER == nil {
		chainDER = [][]byte{}
	}
	return &signer.Issued{
		LeafDER: leafDER, ChainDER: chainDER, PrivateKeyPKCS8: keyDER,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Serial: fmt.Sprintf("%x", leaf.SerialNumber),
	}, keyType, nil
}

// normalizeKeyPEM decodes a PEM private key of any of the three encodings
// this endpoint accepts (PKCS#1, SEC1, PKCS#8) and re-marshals it as
// PKCS#8, the shape certstore always stores.
func normalizeKeyPEM(keyPEM []byte) ([]byte, error) {
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || !strings.HasSuffix(kb.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("no private key PEM block")
	}
	var key any
	var err error
	switch kb.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot parse: %w", err)
	}
	return x509.MarshalPKCS8PrivateKey(key)
}

// publicKeysEqual compares two crypto.PublicKey values through the Equal
// method every stdlib key type (*rsa.PublicKey, *ecdsa.PublicKey,
// ed25519.PublicKey) implements.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

// uploadNames derives a certificate's common name and SANs from its own
// leaf, lower-cased: an upload's names come from the certificate itself,
// not from a caller-supplied CommonName/SANs pair the way CertInput's do
// (CertificateUpload/CertificateVersionUpload carry no such fields).
func uploadNames(leaf *x509.Certificate) (string, []string, error) {
	if len(leaf.DNSNames) == 0 {
		return "", nil, &ValidationError{"certificatePem", "the leaf certificate has no DNS names"}
	}
	names := make([]string, len(leaf.DNSNames))
	for i, n := range leaf.DNSNames {
		names[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
	}
	return names[0], names[1:], nil
}

// uploadStatus reports whether iss is still valid (active) or already past
// its NotAfter (expired), the only two statuses an unmanaged certificate
// (managed=false, never renewed) can ever be in.
func uploadStatus(iss *signer.Issued) string {
	if iss.NotAfter.After(time.Now()) {
		return StatusActive
	}
	return StatusExpired
}

// UploadCertificate stores in as a brand-new unmanaged certificate (R10):
// CreateExternalCertificate, certstore.Insert, then SetCurrentVersion, all
// in one transaction (Store.Begin, shared across issuance.Store and
// certstore the way IssueWorker.succeed shares its own). Names and status
// come from the leaf itself (CertificateUpload has no name/sans fields of
// its own besides "name"). A name already used by another certificate of
// this org is a 409 ConflictError, not the usual 422 a duplicate
// CreateCertificate name gives — R10's brief calls for 409 specifically for
// uploads. Audited certificate.upload, then every registered Listener runs
// (OnVersion), the same as an ordinary issuance.
func (s *Service) UploadCertificate(ctx context.Context, orgID uuid.UUID, name string, in UploadInput) (Certificate, certstore.Version, error) {
	iss, keyType, err := ParseUpload(in)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	leaf, err := x509.ParseCertificate(iss.LeafDER)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	cn, sans, err := uploadNames(leaf)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	status := uploadStatus(iss)

	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := s.Store.CreateExternalCertificate(ctx, tx, orgID, strings.TrimSpace(name), cn, sans, Defaults{}, status)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	v, err := s.Certs.Insert(ctx, tx, c.ID, iss, string(keyType), certstore.InsertOpts{Source: "uploaded"})
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	c, err = s.Store.SetCurrentVersion(ctx, tx, c.ID, v.ID, cn, sans, status, nil)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	s.auditCertificateWrite(ctx, c, "upload", map[string]any{"name": c.Name, "commonName": c.CommonName, "sans": c.SANs})
	s.notifyVersion(ctx, c.ID, v.ID)
	return c, v, nil
}

// UploadVersion adds an uploaded PEM/PKCS#12 version to an existing
// certificate: certstore.Insert then SetCurrentVersion, in one transaction.
// Refused (409 ConflictError) when the certificate is still managed by
// CertForge: uploads only ever apply to a certificate CertForge does not
// renew itself. Names and status are recomputed from the newly uploaded
// leaf, exactly like UploadCertificate — an uploaded version can cover
// different names than the certificate's current definition. Audited
// certificate.version_uploaded, then every registered Listener runs
// (OnVersion). The caller (the API handler) checks beforehand whether a
// keyless upload would strand a live grant that needs a key (409); that
// check reaches into internal/agents, which this package must not import.
func (s *Service) UploadVersion(ctx context.Context, orgID, certID uuid.UUID, in UploadInput) (Certificate, certstore.Version, error) {
	cur, err := s.Store.GetCertificate(ctx, orgID, certID)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	if cur.Managed {
		return Certificate{}, certstore.Version{}, &ConflictError{Msg: "certificate is managed by CertForge; upload a version only for an unmanaged certificate"}
	}
	iss, keyType, err := ParseUpload(in)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	leaf, err := x509.ParseCertificate(iss.LeafDER)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	cn, sans, err := uploadNames(leaf)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	status := uploadStatus(iss)

	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	v, err := s.Certs.Insert(ctx, tx, certID, iss, string(keyType), certstore.InsertOpts{Source: "uploaded"})
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	c, err := s.Store.SetCurrentVersion(ctx, tx, certID, v.ID, cn, sans, status, nil)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	s.auditCertificateWrite(ctx, c, "version_uploaded", map[string]any{"name": c.Name, "commonName": c.CommonName, "sans": c.SANs})
	s.notifyVersion(ctx, c.ID, v.ID)
	return c, v, nil
}
