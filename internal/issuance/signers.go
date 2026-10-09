package issuance

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
	"github.com/metril/certforge/internal/signer/localca"
	"github.com/metril/certforge/internal/signer/vaultpki"
	"github.com/metril/certforge/internal/vault"
)

// localCASubject is a localca CA's public subject, stored in the cas.config
// column (issuance.CA.Config's "subject" field, Shared contract
// LocalCaConfig.Subject).
type localCASubject struct {
	CommonName   string `json:"commonName"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
}

// retiredIssuer is one entry of a localca CA's public config.retired[]: the
// certificate a rotation retired, kept (with its key, sealed separately in
// secret_cfg) until its own NotAfter so leaves it issued can still be
// revoked (Deviations R4/R10).
type retiredIssuer struct {
	PEM      string    `json:"pem"`
	NotAfter time.Time `json:"notAfter"`
	Serial   string    `json:"serial"`
}

// revokedEntry is one revoked leaf, recorded against the CA's config
// column by caRecorder.Revoke. Only revokedCount (its length) ever reaches
// the API; internal/api's caOut strips the array itself.
type revokedEntry struct {
	Serial       string    `json:"serial"`
	IssuerSerial string    `json:"issuerSerial"`
	At           time.Time `json:"at"`
	Reason       int       `json:"reason"`
	// NotAfter is the leaf's expiry; entries past it are dropped from the
	// CRL and pruned. Zero for entries recorded before it was stored, which
	// are kept.
	NotAfter time.Time `json:"notAfter,omitempty"`
}

// localCAConfig is the full shape of a localca CA's public cas.config
// column: the Shared contract's LocalCaConfig public fields, plus the
// read-only imported/issuingPem/retired/revoked fields. internal/api's
// caOut renders this to the wire shape (revoked -> revokedCount, retired[]
// entries gain crlUrl, chainPem is stripped — an internal reconstruction
// aid, not part of the LocalCaConfig contract). ChainPem is every
// certificate above the issuing certificate, in order (the full imported
// chain, or just the root for a generated CA) — set once at create and
// never touched by Rotate, since only the issuing certificate changes
// across a rotation, never what is above it. Kept here (not a second
// column) since it is public, CA-wide, and shared by every issuer, current
// or retired.
type localCAConfig struct {
	Subject              localCASubject  `json:"subject"`
	KeyType              string          `json:"keyType"`
	RootValidityYears    int             `json:"rootValidityYears"`
	IssuingValidityYears int             `json:"issuingValidityYears"`
	MaxLeafDays          int             `json:"maxLeafDays"`
	CRL                  bool            `json:"crl"`
	Imported             bool            `json:"imported"`
	IssuingPem           string          `json:"issuingPem"`
	ChainPem             string          `json:"chainPem"`
	Retired              []retiredIssuer `json:"retired"`
	Revoked              []revokedEntry  `json:"revoked"`
}

func (c localCAConfig) toSignerConfig() localca.Config {
	return localca.Config{
		Subject:              localca.Subject{CommonName: c.Subject.CommonName, Organization: c.Subject.Organization, Country: c.Subject.Country},
		KeyType:              signer.KeyType(c.KeyType),
		RootValidityYears:    c.RootValidityYears,
		IssuingValidityYears: c.IssuingValidityYears,
		MaxLeafDays:          c.MaxLeafDays,
		CRL:                  c.CRL,
	}
}

// retiredSecretKey is one retired issuing key, sealed inside secret_cfg,
// matched to its public retiredIssuer entry by serial.
type retiredSecretKey struct {
	Serial   string    `json:"serial"`
	Key      []byte    `json:"key"`
	NotAfter time.Time `json:"notAfter"`
}

// localCASecretCfg is the sealed JSON stored in cas.secret_cfg for a
// localca CA (Task 7 brief's Contract details). RootKey is nil for an
// import (there is no root key to hold — Rotate is then 422). ImportKeyPem
// is kept only so storedSecrets can report it held; issuingKey (not the
// PEM) is what Issue/Revoke actually sign with.
type localCASecretCfg struct {
	RootKey      []byte             `json:"rootKey,omitempty"`
	IssuingKey   []byte             `json:"issuingKey"`
	Retired      []retiredSecretKey `json:"retired"`
	ImportKeyPem string             `json:"importKeyPem,omitempty"`
}

// pemEncodeCert returns c's PEM encoding.
func pemEncodeCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// parsePEMCert decodes the first CERTIFICATE block of s.
func parsePEMCert(s string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, errors.New("issuance: corrupt stored certificate PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// parsePEMCertChain decodes every CERTIFICATE PEM block in s, in order
// (mirrors localca.Import's own unexported parseCertChain; duplicated
// rather than exported from Task 6's package, since it is a handful of
// lines and issuance has no other reason to depend on localca beyond its
// public Material/Config/Signer surface).
func parsePEMCertChain(s string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(s)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("issuance: parse chain certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// materialFromParts rebuilds a localca.Material for one issuer (current or
// retired) from its stored PEM, its PKCS#8 key, and the CA's chain (every
// certificate above the issuing certificate, in order — localCAConfig's
// ChainPem, shared by every issuer since only the issuing certificate
// itself changes across a rotation). The chain's last certificate is
// Material.Root only when it is actually self-signed (the same check
// localca.Import itself uses): an import whose top-of-chain certificate is
// not self-signed has no local root, and the whole chain is returned as-is
// for the caller to trust as given.
func materialFromParts(issuingPEM string, issuingKeyPKCS8 []byte, chainPEM string) (localca.Material, error) {
	issuing, err := parsePEMCert(issuingPEM)
	if err != nil {
		return localca.Material{}, err
	}
	key, err := x509.ParsePKCS8PrivateKey(issuingKeyPKCS8)
	if err != nil {
		return localca.Material{}, fmt.Errorf("issuance: parse issuing key: %w", err)
	}
	signerKey, ok := key.(stdcrypto.Signer)
	if !ok {
		return localca.Material{}, fmt.Errorf("issuance: issuing key of type %T is not a signer", key)
	}
	chain, err := parsePEMCertChain(chainPEM)
	if err != nil {
		return localca.Material{}, err
	}
	mat := localca.Material{Issuing: issuing, IssuingKey: signerKey, Chain: chain}
	if n := len(chain); n > 0 {
		last := chain[n-1]
		if bytes.Equal(last.RawIssuer, last.RawSubject) && last.CheckSignatureFrom(last) == nil {
			mat.Root = last
		}
	}
	return mat, nil
}

// clearSecretCfg zeroes every private-key byte slice in sc — the root key,
// the current issuing key, and every retired issuing key — once the
// caller is done with it (Security constraint: CA private-key bytes never
// outlive the call that needs them).
func clearSecretCfg(sc *localCASecretCfg) {
	clear(sc.RootKey)
	clear(sc.IssuingKey)
	for i := range sc.Retired {
		clear(sc.Retired[i].Key)
	}
}

// revokedExpired reports whether e's leaf had expired by now. An entry
// without a recorded NotAfter is never expired.
func revokedExpired(e revokedEntry, now time.Time) bool {
	return !e.NotAfter.IsZero() && e.NotAfter.Before(now)
}

// caRecorder implements localca.Recorder against a CA row already locked
// FOR UPDATE inside the caller's transaction (Store.RevokeVersion):
// Revoke appends to config.revoked and bumps crl_number in one UPDATE
// (Task 7 brief: "localca appends to revoked, crl_number++").
type caRecorder struct {
	q     *sqlcgen.Queries // tx-scoped
	orgID uuid.UUID
	row   sqlcgen.Ca // mutated in place; Revoke is called at most once per Signer.Revoke
}

func (r *caRecorder) Revoke(ctx context.Context, serial, issuerSerial string, reason int, at, notAfter time.Time) error {
	var cfg localCAConfig
	if err := json.Unmarshal(r.row.Config, &cfg); err != nil {
		return err
	}
	// Entries for leaves that have expired no longer belong on the CRL.
	cfg.Revoked = slices.DeleteFunc(cfg.Revoked, func(e revokedEntry) bool { return revokedExpired(e, at) })
	cfg.Revoked = append(cfg.Revoked, revokedEntry{Serial: serial, IssuerSerial: issuerSerial, At: at, Reason: reason, NotAfter: notAfter})
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	updated, err := r.q.UpdateCACrypto(ctx, sqlcgen.UpdateCACryptoParams{
		ID: r.row.ID, OrgID: r.orgID, Config: raw, SecretCfg: r.row.SecretCfg,
		NotBefore: r.row.NotBefore, NotAfter: r.row.NotAfter, CrlNumber: r.row.CrlNumber + 1,
	})
	if err != nil {
		return err
	}
	r.row = updated
	return nil
}

// SignerFactory builds a signer.Signer for a CA: the single construction
// path both IssueWorker and ARIPollWorker use (their NewSigner field), and
// RevokeVersion's own localca/vaultpki dispatch. Store supplies the CA's key
// material; Vault builds a vaultpki CA's client; BaseURL resolves the
// server's public base URL (general.baseUrl) fresh per call, for a leaf's
// CRL distribution point.
type SignerFactory struct {
	Store   *Store
	Vault   *vault.Provider
	BaseURL func(ctx context.Context) string
}

// New builds ca's current-issuer signer.
func (f *SignerFactory) New(ctx context.Context, ca CA) (signer.Signer, error) {
	switch ca.Type {
	case CATypeLocalCA:
		return f.Store.localCASignerCurrent(ctx, ca, f.baseURL(ctx))
	case CATypeVaultPKI:
		return f.newVaultPKISigner(ctx, ca)
	case CATypeACME:
		return acmesigner.New(acmesigner.Config{DirectoryURL: ca.DirectoryURL, TrustBundlePEM: ca.TrustBundlePEM}), nil
	default:
		return nil, signer.ErrNotSupported
	}
}

// newVaultPKISigner builds a vaultpki Signer over ca's stored mount/role/ttl
// and the shared Vault client Vault.Client builds from live settings.
func (f *SignerFactory) newVaultPKISigner(ctx context.Context, ca CA) (signer.Signer, error) {
	if f.Vault == nil {
		return nil, vault.ErrNotConfigured
	}
	vc, err := f.Vault.Client(ctx)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(ca.Config)
	if err != nil {
		return nil, err
	}
	var cfg vaultPKIConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return vaultpki.New(vc, vaultpki.Config{Mount: cfg.Mount, Role: cfg.Role, TTL: cfg.TTL}), nil
}

func (f *SignerFactory) baseURL(ctx context.Context) string {
	if f.BaseURL == nil {
		return ""
	}
	return f.BaseURL(ctx)
}

// localCASignerCurrent builds a Signer over ca's current issuing material
// (not the caller's already-open transaction, if any: a plain read used by
// the future issuance path, Task 9). Revoking against a retired issuer
// calls localCASignerFromRow directly instead, inside RevokeVersion's own
// transaction with a specific issuerSerial, since only that path ever
// needs to lock and mutate the CA row.
func (s *Store) localCASignerCurrent(ctx context.Context, ca CA, baseURL string) (signer.Signer, error) {
	row, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: ca.ID, OrgID: ca.OrgID})
	if err != nil {
		return nil, notFound(err)
	}
	return s.localCASignerFromRow(ctx, s.q, row, baseURL, "")
}

// localCASignerFromRow builds a Signer for row's current issuer (issuer ==
// "") or a specific one by hex serial (current or retired): the "carry
// forward" from Task 6 that Revoke must check which issuer signed the leaf
// and build a Signer over that issuer's own Material, current or retired.
func (s *Store) localCASignerFromRow(ctx context.Context, q *sqlcgen.Queries, row sqlcgen.Ca, baseURL, issuerSerial string) (*localca.Signer, error) {
	mat, cfg, err := s.CASecret(ctx, row, issuerSerial)
	if err != nil {
		return nil, err
	}
	var pub localCAConfig
	if err := json.Unmarshal(row.Config, &pub); err != nil {
		return nil, err
	}
	opts := localca.Opts{CAID: row.ID, Now: time.Now}
	if pub.CRL {
		opts.BaseURL = baseURL
	}
	rec := &caRecorder{q: q, orgID: row.OrgID, row: row}
	return localca.New(mat, cfg, rec, opts), nil
}

// currentIssuerSerial returns cfg's current issuing certificate's hex
// serial, or "" when it cannot be parsed (localCASignerFromRow then falls
// through to retiredMaterial, which will itself fail to find a match).
func currentIssuerSerial(cfg localCAConfig) string {
	c, err := parsePEMCert(cfg.IssuingPem)
	if err != nil {
		return ""
	}
	return c.SerialNumber.Text(16)
}

// knownIssuerSerial reports whether serial names cfg's current issuer ("" or
// its hex serial) or one of its retired issuers.
func knownIssuerSerial(cfg localCAConfig, serial string) bool {
	if serial == "" || serial == currentIssuerSerial(cfg) {
		return true
	}
	for _, ri := range cfg.Retired {
		if ri.Serial == serial {
			return true
		}
	}
	return false
}

// retiredMaterial looks up a retired issuer by hex serial in both cfg's
// public entries (the certificate) and sc's sealed entries (its key); the
// chain above it (chainPEM) is the same for every issuer of this CA.
func retiredMaterial(cfg localCAConfig, sc localCASecretCfg, chainPEM, serial string) (localca.Material, error) {
	var pemStr string
	for _, ri := range cfg.Retired {
		if ri.Serial == serial {
			pemStr = ri.PEM
			break
		}
	}
	if pemStr == "" {
		return localca.Material{}, &ValidationError{"issuerSerial", "no such issuer for this CA"}
	}
	var keyBytes []byte
	for _, rk := range sc.Retired {
		if rk.Serial == serial {
			keyBytes = rk.Key
			break
		}
	}
	if len(keyBytes) == 0 {
		return localca.Material{}, &ValidationError{"issuerSerial", "no such issuer for this CA"}
	}
	return materialFromParts(pemStr, keyBytes, chainPEM)
}

// CASecret returns issuer's Material and signer Config (current when
// issuerSerial is ""): the CA lifecycle's single source of truth for
// unsealing and reconstructing a localca CA's key material, used by the
// signer-building path (localCASignerFromRow) and directly by CRL below,
// which needs only the issuing certificate and its key, not a full Signer.
// The returned Material's private key bytes are the caller's alone to use
// and let go of; sc's own copies are cleared before this returns.
func (s *Store) CASecret(ctx context.Context, row sqlcgen.Ca, issuerSerial string) (localca.Material, localca.Config, error) {
	var cfg localCAConfig
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return localca.Material{}, localca.Config{}, err
	}
	var sc localCASecretCfg
	if err := s.openJSON(ctx, row.SecretCfg, &sc); err != nil {
		return localca.Material{}, localca.Config{}, err
	}
	defer clearSecretCfg(&sc)
	// chainPem was added by the batch-3 review fix (f5fccdc); a row
	// created before it has none. Falling back to the CA's own
	// trust_bundle_pem — a single certificate, but parsePEMCertChain reads
	// it as a one-entry chain just fine — keeps such a row's Material.Root
	// and Chain from silently going empty instead of losing the root.
	chainPEM := cfg.ChainPem
	if chainPEM == "" {
		chainPEM = row.TrustBundlePem
	}
	var mat localca.Material
	var err error
	switch issuerSerial {
	case "", currentIssuerSerial(cfg):
		mat, err = materialFromParts(cfg.IssuingPem, sc.IssuingKey, chainPEM)
	default:
		mat, err = retiredMaterial(cfg, sc, chainPEM, issuerSerial)
	}
	return mat, cfg.toSignerConfig(), err
}

// CACRLNumber returns caID's current crl_number, for the public CRL
// route's cache key: keying on it (Shared contract) means a revocation's
// crl_number bump is visible on the very next request instead of waiting
// out the cache's own TTL.
func (s *Store) CACRLNumber(ctx context.Context, caID uuid.UUID) (int64, error) {
	row, err := s.q.GetCAByID(ctx, caID)
	if err != nil {
		return 0, ErrNotFound
	}
	return row.CrlNumber, nil
}

// CRL builds a DER CRL for caID's issuer (the current one when
// issuerSerial is ""), signed by that issuer's own key. Not org-scoped:
// the CRL routes are public. ErrNotFound covers every reason the route
// answers 404 for (Shared contract: unknown id, non-localca CA, crl:
// false, unknown issuer serial) — the route never distinguishes them, so a
// probing client learns nothing.
func (s *Store) CRL(ctx context.Context, caID uuid.UUID, issuerSerial string) ([]byte, error) {
	row, err := s.q.GetCAByID(ctx, caID)
	if err != nil {
		return nil, ErrNotFound
	}
	if row.Type != CATypeLocalCA {
		return nil, ErrNotFound
	}
	var cfg localCAConfig
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return nil, err
	}
	if !cfg.CRL {
		return nil, ErrNotFound
	}

	// An unauthenticated caller can name any serial: reject an unknown one
	// from the public config before anything is unsealed or written.
	if !knownIssuerSerial(cfg, issuerSerial) {
		return nil, ErrNotFound
	}
	key := issuerSerial
	if key == "" {
		key = currentIssuerSerial(cfg)
	}

	// Fast path: the stored CRL, while the revoked set is unchanged and it
	// is still in the first half of its validity.
	if stored, err := s.q.GetCACRL(ctx, sqlcgen.GetCACRLParams{CaID: caID, IssuerSerial: key}); err == nil && crlFresh(stored, row.CrlNumber, time.Now()) {
		return stored.Der, nil
	}

	// Slow path: serialise signers on the CA row (and with revocations),
	// re-check, then sign with the next cRLNumber (RFC 5280 5.2.3).
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	row, err = q.LockCAByID(ctx, caID)
	if err != nil {
		return nil, ErrNotFound
	}
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return nil, err
	}
	now := time.Now()
	number := row.CrlNumber + 1 // above any number served before CRLs were stored
	if stored, err := q.GetCACRL(ctx, sqlcgen.GetCACRLParams{CaID: caID, IssuerSerial: key}); err == nil {
		if crlFresh(stored, row.CrlNumber, now) {
			return stored.Der, nil
		}
		number = max(number, stored.CrlNumber+1)
	}

	mat, _, err := s.CASecret(ctx, row, issuerSerial)
	if err != nil {
		// Covers a corrupt stored certificate/key (and, as a backstop, an
		// unknown issuerSerial): the route never distinguishes reasons.
		return nil, ErrNotFound
	}
	issuerHex := mat.Issuing.SerialNumber.Text(16)
	var revoked []localca.Revoked
	for _, re := range cfg.Revoked {
		if re.IssuerSerial != issuerHex || revokedExpired(re, now) {
			continue
		}
		sn, ok := new(big.Int).SetString(re.Serial, 16)
		if !ok {
			continue
		}
		revoked = append(revoked, localca.Revoked{Serial: sn, RevokedAt: re.At, ReasonCode: re.Reason})
	}
	der, err := localca.BuildCRL(mat.Issuing, mat.IssuingKey, revoked, big.NewInt(number), now)
	if err != nil {
		return nil, err
	}
	if err := q.UpsertCACRL(ctx, sqlcgen.UpsertCACRLParams{CaID: caID, IssuerSerial: key, CrlNumber: number,
		Revision: row.CrlNumber, Der: der, ThisUpdate: now, NextUpdate: now.Add(localca.CRLValidity)}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return der, nil
}

// crlFresh reports whether a stored CRL still reflects the CA's revoked set
// (revision) and has more than half of its validity left.
func crlFresh(c sqlcgen.CaCrl, revision int64, now time.Time) bool {
	return c.Revision == revision && now.Before(c.ThisUpdate.Add(c.NextUpdate.Sub(c.ThisUpdate)/2))
}

// issuerSerialForLeaf decides which of cfg's issuers signed leaf, by
// AuthorityKeyId: "" (found=true) selects the current issuer, both when the
// AKI matches it and when leaf carries no AKI at all (matching
// localca.Signer.Revoke's own leniency); a retired issuer's hex serial
// selects that one. found is false when leaf matches neither — Task 7
// brief's carry-forward from Task 6: Revoke must check the issuer and
// build a Signer over the matching one, current or retired.
func issuerSerialForLeaf(cfg localCAConfig, leaf *x509.Certificate) (serial string, found bool) {
	if cur, err := parsePEMCert(cfg.IssuingPem); err == nil {
		if len(leaf.AuthorityKeyId) == 0 || bytes.Equal(leaf.AuthorityKeyId, cur.SubjectKeyId) {
			return "", true
		}
	}
	for _, ri := range cfg.Retired {
		if rc, err := parsePEMCert(ri.PEM); err == nil && bytes.Equal(leaf.AuthorityKeyId, rc.SubjectKeyId) {
			return ri.Serial, true
		}
	}
	return "", false
}

// localCAInput is a localca CA's create/update config, parsed from
// CAInput.Config and defaulted (Shared contract LocalCaConfig).
type localCAInput struct {
	Subject              localCASubject
	KeyType              string
	RootValidityYears    int
	IssuingValidityYears int
	MaxLeafDays          int
	CRL                  bool
	ImportPEM            string
	ImportKeyPEM         string
}

// localCAConfigWire is LocalCaConfig's wire shape with every field
// optional, so parseLocalCAInput can tell "omitted" (default applies) from
// an explicit zero value.
type localCAConfigWire struct {
	Subject              *localCASubject `json:"subject"`
	KeyType              *string         `json:"keyType"`
	RootValidityYears    *int            `json:"rootValidityYears"`
	IssuingValidityYears *int            `json:"issuingValidityYears"`
	MaxLeafDays          *int            `json:"maxLeafDays"`
	CRL                  *bool           `json:"crl"`
	ImportPem            *string         `json:"importPem"`
	ImportKeyPem         *string         `json:"importKeyPem"`
}

func parseLocalCAInput(raw map[string]any) (localCAInput, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return localCAInput{}, err
	}
	var w localCAConfigWire
	if err := json.Unmarshal(b, &w); err != nil {
		return localCAInput{}, &ValidationError{"config", "invalid localca config: " + err.Error()}
	}
	in := localCAInput{KeyType: string(signer.EC256), RootValidityYears: 10, IssuingValidityYears: 3, MaxLeafDays: 397, CRL: true}
	if w.Subject != nil {
		in.Subject = *w.Subject
	}
	if w.KeyType != nil {
		in.KeyType = *w.KeyType
	}
	if w.RootValidityYears != nil {
		in.RootValidityYears = *w.RootValidityYears
	}
	if w.IssuingValidityYears != nil {
		in.IssuingValidityYears = *w.IssuingValidityYears
	}
	if w.MaxLeafDays != nil {
		in.MaxLeafDays = *w.MaxLeafDays
	}
	if w.CRL != nil {
		in.CRL = *w.CRL
	}
	if w.ImportPem != nil {
		in.ImportPEM = *w.ImportPem
	}
	if w.ImportKeyPem != nil {
		in.ImportKeyPEM = *w.ImportKeyPem
	}
	return in, nil
}

var countryCodeRe = regexp.MustCompile(`^[A-Z]{2}$`)

// validate checks in's shape (Shared contract LocalCaConfig bounds); it
// does not check import material itself (localca.Import/Generate do that).
func (in localCAInput) validate() error {
	cn := strings.TrimSpace(in.Subject.CommonName)
	if cn == "" || len(cn) > 64 {
		return &ValidationError{"config.subject.commonName", "required, 1-64 characters"}
	}
	if len(in.Subject.Organization) > 64 {
		return &ValidationError{"config.subject.organization", "at most 64 characters"}
	}
	if in.Subject.Country != "" && !countryCodeRe.MatchString(in.Subject.Country) {
		return &ValidationError{"config.subject.country", "must be a 2-letter ISO 3166-1 alpha-2 code"}
	}
	if !signer.KeyType(in.KeyType).Valid() {
		return &ValidationError{"config.keyType", "must be one of ec256, ec384, rsa2048, rsa4096"}
	}
	if in.RootValidityYears < 1 || in.RootValidityYears > 30 {
		return &ValidationError{"config.rootValidityYears", "must be 1..30"}
	}
	if in.IssuingValidityYears < 1 || in.IssuingValidityYears > 10 {
		return &ValidationError{"config.issuingValidityYears", "must be 1..10"}
	}
	if in.MaxLeafDays < 1 || in.MaxLeafDays > 825 {
		return &ValidationError{"config.maxLeafDays", "must be 1..825"}
	}
	if (in.ImportPEM == "") != (in.ImportKeyPEM == "") {
		return &ValidationError{"config.importPem", "importPem and importKeyPem must both be given or both omitted"}
	}
	return nil
}

func (in localCAInput) toSignerConfig() localca.Config {
	return localCAConfig{Subject: in.Subject, KeyType: in.KeyType, RootValidityYears: in.RootValidityYears,
		IssuingValidityYears: in.IssuingValidityYears, MaxLeafDays: in.MaxLeafDays, CRL: in.CRL}.toSignerConfig()
}
