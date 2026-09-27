package issuance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
)

// KeylessGrantHook reports whether certID has a live grant whose layout or
// deploy target needs a key (R10's keyless-grant rule, the upload
// direction): UploadVersion calls it, inside its own transaction, right
// after locking the certificate row FOR UPDATE, before accepting a keyless
// version. nil disables the check (tests that don't exercise grants).
// Wired to agents.LiveGrantsNeedKeyTx in production (cmd/certforge/serve.go)
// — a plain function value, not a *agents.Service method bound here,
// because this package must not import internal/agents (R7); q is always
// tx-scoped (s.Store.q.WithTx(tx)), the same transaction UploadVersion's
// own writes run in, so this read and a concurrent createGrant/updateGrant
// (which locks the same certificate row FOR KEY SHARE before its own
// needsKey check, see agents.checkRefs) can never each act on a view of
// the other that is already stale by the time either commits.
type KeylessGrantHook func(ctx context.Context, q *sqlcgen.Queries, certID uuid.UUID) (bool, error)

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
	field := "certificatePem"

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
		field = "pkcs12Base64"
		// go-pkcs12's DecodeChain errors "private key missing" whenever the
		// bundle has none, so key is never nil here on a nil error: a
		// PKCS#12 upload always carries a key (documented in
		// docs/certificates.md#upload); there is no keyless PKCS#12 branch
		// to handle.
		key, cert, caCerts, err := pkcs12.DecodeChain(in.PKCS12, in.Password)
		if err != nil {
			return nil, "", &ValidationError{"pkcs12Base64", "cannot decode: " + err.Error()}
		}
		leafDER = cert.Raw
		for _, c := range caCerts {
			chainDER = append(chainDER, c.Raw)
		}
		signerKey, ok := key.(crypto.Signer)
		if !ok {
			return nil, "", &ValidationError{"pkcs12Base64", fmt.Sprintf("unsupported key type %T", key)}
		}
		if keyDER, err = x509.MarshalPKCS8PrivateKey(signerKey); err != nil {
			return nil, "", &ValidationError{"pkcs12Base64", "cannot marshal key: " + err.Error()}
		}
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, "", &ValidationError{field, "cannot parse leaf: " + err.Error()}
	}
	if chainDER, err = validateChain(leaf, chainDER, field); err != nil {
		return nil, "", err
	}

	// keyField is where a key-specific problem (parse failure, unsupported
	// type, or a mismatch against the leaf) is reported: privateKeyPem for
	// a separately supplied PEM key, pkcs12Base64 for a PKCS#12 key (there
	// is no separate key field to name there), or field itself
	// (certificatePem/pkcs12Base64) when there is no key at all and the
	// leaf's own public key is what KeyTypeOf goes on to reject.
	keyField := field
	if len(in.PrivateKeyPEM) > 0 {
		keyField = "privateKeyPem"
	}
	if keyDER != nil {
		key, err := x509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			return nil, "", &ValidationError{keyField, "cannot parse key: " + err.Error()}
		}
		signerKey, ok := key.(crypto.Signer)
		if !ok {
			return nil, "", &ValidationError{keyField, fmt.Sprintf("unsupported key type %T", key)}
		}
		if !publicKeysEqual(leaf.PublicKey, signerKey.Public()) {
			return nil, "", &ValidationError{keyField, "does not match the certificate"}
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

// validateChain drops any chain entry byte-identical to leaf (a leaf
// repeated in the chain would otherwise render fullchain with it twice),
// then links the rest into signing order starting from leaf: at each step
// the pool member whose Subject matches the current certificate's Issuer
// is required to satisfy CheckSignatureFrom against it, so a chain that
// does not actually sign the certificate above it (including the very
// first link, which must sign leaf itself) or that includes an unrelated
// certificate never passing raises a 422 on field, instead of being stored
// out of order or unverified. Bag/submission order does not matter: PEM
// concatenation order and PKCS#12 bag order are both just a starting pool.
func validateChain(leaf *x509.Certificate, chainDER [][]byte, field string) ([][]byte, error) {
	var pool []*x509.Certificate
	for _, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &ValidationError{field, "cannot parse chain certificate: " + err.Error()}
		}
		if bytes.Equal(c.Raw, leaf.Raw) {
			continue // the leaf itself, repeated in the chain; drop it
		}
		pool = append(pool, c)
	}
	ordered := make([][]byte, 0, len(pool))
	cur := leaf
	for len(pool) > 0 {
		idx := slices.IndexFunc(pool, func(c *x509.Certificate) bool { return bytes.Equal(c.RawSubject, cur.RawIssuer) })
		if idx < 0 {
			return nil, &ValidationError{field, "the chain does not lead from the certificate to every entry provided"}
		}
		next := pool[idx]
		if err := cur.CheckSignatureFrom(next); err != nil {
			return nil, &ValidationError{field, "a chain certificate did not sign the certificate above it: " + err.Error()}
		}
		ordered = append(ordered, next.Raw)
		cur = next
		pool = slices.Delete(pool, idx, idx+1)
	}
	return ordered, nil
}

// publicKeysEqual compares two crypto.PublicKey values through the Equal
// method every stdlib key type (*rsa.PublicKey, *ecdsa.PublicKey,
// ed25519.PublicKey) implements.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

// uploadNames derives a certificate's common name and SANs from its own
// leaf: an upload's names come from the certificate itself, not from a
// caller-supplied CommonName/SANs pair the way CertInput's do
// (CertificateUpload/CertificateVersionUpload carry no such fields). Only
// the DNS SANs are considered — a leaf with IP SANs but no DNS SAN at all
// (leaf.DNSNames empty) is rejected outright, since CertForge's own
// certificate model is DNS-name-based throughout (docs/certificates.md#upload
// documents this). When the leaf's subject CN is itself one of the DNS
// SANs, it is moved first (matching how an ordinary CertForge-issued
// certificate is always named after its own CommonName); otherwise the
// first SAN, in whatever order the leaf lists them, stands in for it. The
// result runs through the same NormalizeNames every other certificate's
// names do (lower-cased, de-duplicated, shape-validated), so an upload
// cannot smuggle in a name CertForge would refuse from any other path.
func uploadNames(leaf *x509.Certificate) (string, []string, error) {
	if len(leaf.DNSNames) == 0 {
		return "", nil, &ValidationError{"certificatePem", "the leaf certificate has no DNS names (a certificate with only IP SANs cannot be uploaded)"}
	}
	cn := leaf.DNSNames[0]
	if leaf.Subject.CommonName != "" {
		if idx := slices.Index(leaf.DNSNames, leaf.Subject.CommonName); idx >= 0 {
			cn = leaf.Subject.CommonName
		}
	}
	sans := make([]string, 0, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		if n != cn {
			sans = append(sans, n)
		}
	}
	names, err := NormalizeNames(cn, sans)
	if err != nil {
		return "", nil, &ValidationError{"certificatePem", err.Error()}
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
// certificate: certstore.Insert then SetCurrentVersion, in one transaction
// that locks the certificate row FOR UPDATE (Store.LockCertificateForUpdate)
// before either write. Refused (409 ConflictError) when the certificate is
// still managed by CertForge: uploads only ever apply to a certificate
// CertForge does not renew itself. Names and status are recomputed from
// the newly uploaded leaf, exactly like UploadCertificate — an uploaded
// version can cover different names than the certificate's current
// definition. Audited certificate.version_uploaded, then every registered
// Listener runs (OnVersion).
//
// A keyless upload is refused (409) when s.KeylessGrantHook (nil in tests
// that don't exercise grants) reports a live grant whose layout or deploy
// target needs a key. The hook runs after the FOR UPDATE lock is held and
// inside this same transaction (fix round 1): agents.checkRefs locks the
// same certificate row FOR KEY SHARE — which conflicts with FOR UPDATE,
// unlike the plain UPDATE SetCurrentVersion alone would have issued
// (implicit FOR NO KEY UPDATE, which does not conflict with FOR KEY
// SHARE) — right before its own needsKey check, so whichever of a
// concurrent createGrant/updateGrant and this call locks the row first is
// fully committed or rolled back before the other's check runs; neither
// can act on a view of the other that is already stale by the time either
// commits.
func (s *Service) UploadVersion(ctx context.Context, orgID, certID uuid.UUID, in UploadInput) (Certificate, certstore.Version, error) {
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
	cur, err := s.Store.LockCertificateForUpdate(ctx, tx, orgID, certID)
	if err != nil {
		return Certificate{}, certstore.Version{}, err
	}
	if cur.Managed {
		return Certificate{}, certstore.Version{}, &ConflictError{Msg: "certificate is managed by CertForge; upload a version only for an unmanaged certificate"}
	}
	if len(iss.PrivateKeyPKCS8) == 0 && s.KeylessGrantHook != nil {
		needsKey, err := s.KeylessGrantHook(ctx, s.Store.q.WithTx(tx), certID)
		if err != nil {
			return Certificate{}, certstore.Version{}, err
		}
		if needsKey {
			return Certificate{}, certstore.Version{}, &ConflictError{Msg: "This certificate has a live grant whose layout or deploy target needs a key; upload a version with a key, or remove those grants first."}
		}
	}
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
