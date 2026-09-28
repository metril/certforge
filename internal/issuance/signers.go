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
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/signer/localca"
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
}

// localCAConfig is the full shape of a localca CA's public cas.config
// column: the Shared contract's LocalCaConfig public fields, plus the
// read-only imported/issuingPem/retired/revoked fields. internal/api's
// caOut renders this to the wire shape (revoked -> revokedCount, retired[]
// entries gain crlUrl).
type localCAConfig struct {
	Subject              localCASubject  `json:"subject"`
	KeyType              string          `json:"keyType"`
	RootValidityYears    int             `json:"rootValidityYears"`
	IssuingValidityYears int             `json:"issuingValidityYears"`
	MaxLeafDays          int             `json:"maxLeafDays"`
	CRL                  bool            `json:"crl"`
	Imported             bool            `json:"imported"`
	IssuingPem           string          `json:"issuingPem"`
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

// materialFromParts rebuilds a localca.Material for one issuer (current or
// retired) from its stored PEM, its PKCS#8 key, and the CA's own trust
// bundle. The trust bundle is the root PEM for a generated CA, or for an
// import either the root (its last chain certificate, when self-signed) or
// the issuing certificate itself (a chainless import) — Import records the
// same rule (localca.Import), so comparing serials tells the two apart
// without a separate "imported" flag: when the trust bundle's certificate
// is the issuing certificate itself, there is no separate root to trust
// through (Material.Root stays nil, matching a chainless Import).
func materialFromParts(issuingPEM string, issuingKeyPKCS8 []byte, trustBundlePEM string) (localca.Material, error) {
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
	mat := localca.Material{Issuing: issuing, IssuingKey: signerKey}
	if trustBundlePEM != "" {
		cand, err := parsePEMCert(trustBundlePEM)
		if err != nil {
			return localca.Material{}, err
		}
		if cand.SerialNumber.Cmp(issuing.SerialNumber) != 0 {
			mat.Root = cand
			mat.Chain = []*x509.Certificate{cand}
		}
	}
	return mat, nil
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

func (r *caRecorder) Revoke(ctx context.Context, serial, issuerSerial string, reason int, at time.Time) error {
	var cfg localCAConfig
	if err := json.Unmarshal(r.row.Config, &cfg); err != nil {
		return err
	}
	cfg.Revoked = append(cfg.Revoked, revokedEntry{Serial: serial, IssuerSerial: issuerSerial, At: at, Reason: reason})
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

// SignerFactory builds a signer.Signer for a CA. Store supplies the CA's
// key material; BaseURL resolves the server's public base URL
// (general.baseUrl) fresh per call, for a leaf's CRL distribution point.
// Task 7 wires the localca case only; Task 9 adds acme and vaultpki and
// removes worker.DefaultSigner (Pre-flight rulings).
type SignerFactory struct {
	Store   *Store
	BaseURL func(ctx context.Context) string
}

// New builds ca's current-issuer signer. Any kind but localca returns
// signer.ErrNotSupported (422 at the API, until Task 9).
func (f *SignerFactory) New(ctx context.Context, ca CA) (signer.Signer, error) {
	if ca.Type != CATypeLocalCA {
		return nil, signer.ErrNotSupported
	}
	return f.Store.localCASignerCurrent(ctx, ca, f.baseURL(ctx))
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
// uses localCASignerForLeaf instead, inside RevokeVersion's own
// transaction, since only that path ever needs to lock and mutate the CA
// row.
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

// retiredMaterial looks up a retired issuer by hex serial in both cfg's
// public entries (the certificate) and sc's sealed entries (its key).
func retiredMaterial(cfg localCAConfig, sc localCASecretCfg, trustBundlePEM, serial string) (localca.Material, error) {
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
	return materialFromParts(pemStr, keyBytes, trustBundlePEM)
}

// CASecret is a thin, exported alias of localCASignerFromRow's material
// step, for the CRL route: it returns issuer's Material (current when
// issuerSerial is "") without building a Signer, since building a CRL
// needs only the issuing certificate and its key, not a full Signer.
func (s *Store) CASecret(ctx context.Context, row sqlcgen.Ca, issuerSerial string) (localca.Material, localca.Config, error) {
	var cfg localCAConfig
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return localca.Material{}, localca.Config{}, err
	}
	var sc localCASecretCfg
	if err := s.openJSON(ctx, row.SecretCfg, &sc); err != nil {
		return localca.Material{}, localca.Config{}, err
	}
	var mat localca.Material
	var err error
	switch issuerSerial {
	case "", currentIssuerSerial(cfg):
		mat, err = materialFromParts(cfg.IssuingPem, sc.IssuingKey, row.TrustBundlePem)
	default:
		mat, err = retiredMaterial(cfg, sc, row.TrustBundlePem, issuerSerial)
	}
	return mat, cfg.toSignerConfig(), err
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
	var sc localCASecretCfg
	if err := s.openJSON(ctx, row.SecretCfg, &sc); err != nil {
		return nil, err
	}

	var issuingPEM string
	var keyBytes []byte
	switch issuerSerial {
	case "", currentIssuerSerial(cfg):
		issuingPEM, keyBytes = cfg.IssuingPem, sc.IssuingKey
	default:
		for _, ri := range cfg.Retired {
			if ri.Serial == issuerSerial {
				issuingPEM = ri.PEM
				break
			}
		}
		if issuingPEM == "" {
			return nil, ErrNotFound
		}
		for _, rk := range sc.Retired {
			if rk.Serial == issuerSerial {
				keyBytes = rk.Key
				break
			}
		}
		if len(keyBytes) == 0 {
			return nil, ErrNotFound
		}
	}

	issuing, err := parsePEMCert(issuingPEM)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	signerKey, ok := key.(stdcrypto.Signer)
	if !ok {
		return nil, fmt.Errorf("issuance: issuing key of type %T is not a signer", key)
	}

	issuerHex := issuing.SerialNumber.Text(16)
	var revoked []localca.Revoked
	for _, re := range cfg.Revoked {
		if re.IssuerSerial != issuerHex {
			continue
		}
		sn, ok := new(big.Int).SetString(re.Serial, 16)
		if !ok {
			continue
		}
		revoked = append(revoked, localca.Revoked{Serial: sn, RevokedAt: re.At, ReasonCode: re.Reason})
	}
	return localca.BuildCRL(issuing, signerKey, revoked, big.NewInt(row.CrlNumber), time.Now())
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
