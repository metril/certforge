package issuance

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
	"github.com/metril/certforge/internal/signer/localca"
)

// CA kinds (Shared contract: CaType enum). Only CATypeACME issues today;
// CATypeLocalCA and CATypeVaultPKI are recognized but rejected as "not
// available yet" until Tasks 7 and 8 build their signers.
const (
	CATypeACME     = "acme"
	CATypeLocalCA  = "localca"
	CATypeVaultPKI = "vaultpki"
)

// CA is an ACME directory, or (from Phase 5A) a private CA. Shared is
// reserved for Phase 2 global CAs. Type, Config, NotBefore, NotAfter and
// CRLNumber are meaningless placeholders for an acme CA (Type is always
// "acme", Config is always empty, the rest are always nil/zero) until a
// private kind can actually be created.
type CA struct {
	ID, OrgID                                          uuid.UUID
	Name, Preset, DirectoryURL, TrustBundlePEM, EABKid string
	HasEAB                                             bool
	Resolvers                                          []string
	Shared                                             bool
	Type                                               string
	Config                                             map[string]any
	NotBefore, NotAfter                                *time.Time
	CRLNumber                                          int64
	CreatedAt, UpdatedAt                               time.Time
}

// CAInput creates or replaces a CA. EABHmac: on create nil/"" = none; on
// update nil or challenge.Unchanged keeps the stored value, "" clears it.
// Type defaults to acme when empty; Config is the kind's public config
// (empty for acme).
type CAInput struct {
	Name, Preset, DirectoryURL, TrustBundlePEM, EABKid string
	EABHmac                                            *string
	Resolvers                                          []string
	Type                                               string
	Config                                             map[string]any
}

// Account is a registered ACME account (key never leaves the store).
type Account struct {
	ID, OrgID, CAID uuid.UUID
	Email, Status   string
	RegistrationURI string
	CreatedAt       time.Time
}

// Staging reports whether ca's preset is the one that does not itself
// enforce ACME rate limits: true only for letsencrypt-staging (Deviations
// R7). A custom directory (Pebble, or anything else reached through
// "custom") is not staging by this signal, so the rate ledger enforces it
// like any production CA — an e2e run raises the limits through settings
// instead.
func (ca CA) Staging() bool {
	p, ok := acmesigner.PresetByCode(ca.Preset)
	return ok && p.Staging
}

func caFromRow(r sqlcgen.Ca) (CA, error) {
	cfg := map[string]any{}
	if len(r.Config) > 0 {
		if err := json.Unmarshal(r.Config, &cfg); err != nil {
			return CA{}, err
		}
	}
	return CA{ID: r.ID, OrgID: r.OrgID, Name: r.Name, Preset: r.Preset, DirectoryURL: r.DirectoryUrl,
		TrustBundlePEM: r.TrustBundlePem, EABKid: r.EabKid, HasEAB: len(r.EabHmac) > 0,
		Resolvers: r.Resolvers, Shared: r.Shared, Type: r.Type, Config: cfg,
		NotBefore: r.NotBefore, NotAfter: r.NotAfter, CRLNumber: r.CrlNumber,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}, nil
}

func accountFromRow(r sqlcgen.AcmeAccount) Account {
	return Account{ID: r.ID, OrgID: r.OrgID, CAID: r.CaID, Email: r.Email, Status: r.Status,
		RegistrationURI: r.RegistrationUri, CreatedAt: r.CreatedAt}
}

func (in *CAInput) normalize() (acmesigner.Preset, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return acmesigner.Preset{}, &ValidationError{"name", "required"}
	}
	if in.Type == "" {
		in.Type = CATypeACME
	}
	switch in.Type {
	case CATypeVaultPKI:
		// Recognized kind, but its signer doesn't exist yet (Task 8).
		return acmesigner.Preset{}, &ValidationError{"type", "not available yet"}
	case CATypeLocalCA:
		if in.EABKid != "" || (in.EABHmac != nil && *in.EABHmac != "") {
			return acmesigner.Preset{}, &ValidationError{"eabKid", "not applicable to a private CA"}
		}
		// preset/directoryUrl/trustBundlePem are acme-only (Shared
		// contract); a private kind's trust anchor is computed by the
		// store itself, never taken from the caller.
		in.Preset, in.DirectoryURL, in.TrustBundlePEM = "", "", ""
		if in.Resolvers == nil {
			in.Resolvers = []string{}
		}
		if in.Config == nil {
			in.Config = map[string]any{}
		}
		return acmesigner.Preset{}, nil
	case CATypeACME:
		// falls through to the acme validation below
	default:
		return acmesigner.Preset{}, &ValidationError{"type", "unknown type " + in.Type}
	}
	if in.Config == nil {
		in.Config = map[string]any{}
	}
	p, ok := acmesigner.PresetByCode(in.Preset)
	if !ok {
		return p, &ValidationError{"preset", "unknown preset " + in.Preset}
	}
	if in.DirectoryURL == "" {
		in.DirectoryURL = p.DirectoryURL
	}
	u, err := url.Parse(in.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return p, &ValidationError{"directoryUrl", "must be an https URL"}
	}
	if in.TrustBundlePEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(in.TrustBundlePEM)) {
		return p, &ValidationError{"trustBundlePem", "contains no PEM certificates"}
	}
	if in.Resolvers == nil {
		in.Resolvers = []string{}
	}
	if err := validateResolvers("resolvers", in.Resolvers); err != nil {
		return p, err
	}
	return p, nil
}

func validateResolvers(field string, rs []string) error {
	for _, r := range rs {
		host := r
		if h, _, err := net.SplitHostPort(r); err == nil {
			host = h
		}
		if host == "" || strings.ContainsAny(host, " /") {
			return &ValidationError{field, "invalid resolver " + r}
		}
	}
	return nil
}

func (s *Store) sealOptional(ctx context.Context, v string) ([]byte, error) {
	if v == "" {
		return nil, nil
	}
	return s.box.Seal(ctx, []byte(v))
}

// CreateCA validates and stores a CA.
func (s *Store) CreateCA(ctx context.Context, orgID uuid.UUID, in CAInput) (CA, error) {
	p, err := in.normalize()
	if err != nil {
		return CA{}, err
	}
	if in.Type == CATypeLocalCA {
		return s.createLocalCA(ctx, orgID, in)
	}
	hmac := ""
	if in.EABHmac != nil {
		hmac = *in.EABHmac
	}
	if hmac == challenge.Unchanged {
		return CA{}, &ValidationError{Field: "eabHmac", Msg: "value is only valid when updating a stored secret"}
	}
	if p.RequiresEAB && (in.EABKid == "" || hmac == "") {
		return CA{}, &ValidationError{"eabKid", p.Name + " requires an EAB key id and HMAC"}
	}
	sealed, err := s.sealOptional(ctx, hmac)
	if err != nil {
		return CA{}, err
	}
	cfg, err := json.Marshal(in.Config)
	if err != nil {
		return CA{}, err
	}
	row, err := s.q.CreateCA(ctx, sqlcgen.CreateCAParams{OrgID: orgID, Name: in.Name, Type: in.Type, Config: cfg, Preset: in.Preset,
		DirectoryUrl: in.DirectoryURL, TrustBundlePem: in.TrustBundlePEM, EabKid: in.EABKid, EabHmac: sealed, Resolvers: in.Resolvers})
	if err != nil {
		return CA{}, dbErr(err, "name")
	}
	return caFromRow(row)
}

// UpdateCA replaces a CA's fields. Changing directoryUrl while an ACME
// account is registered against the CA is rejected (409): the account's key
// is enrolled with the old ACME server, not the new one, so silently
// repointing the CA would orphan it. CountCAUsers also counts certificates
// and issuance defaults that pin this CA by id; those would just re-resolve
// against the new directory on their next issuance, but are included too
// since they're the same "in use" check DeleteCA already uses.
func (s *Store) UpdateCA(ctx context.Context, orgID, id uuid.UUID, in CAInput) (CA, error) {
	cur, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: id, OrgID: orgID})
	if err != nil {
		return CA{}, notFound(err)
	}
	p, err := in.normalize()
	if err != nil {
		return CA{}, err
	}
	if in.Type != cur.Type {
		return CA{}, &ValidationError{"type", "type cannot change"}
	}
	if in.Type == CATypeLocalCA {
		return s.updateLocalCA(ctx, orgID, id, cur, in)
	}
	if in.DirectoryURL != cur.DirectoryUrl {
		n, err := s.q.CountCAUsers(ctx, id)
		if err != nil {
			return CA{}, err
		}
		if n > 0 {
			return CA{}, &InUseError{Users: n}
		}
	}
	sealed := cur.EabHmac
	if in.EABHmac != nil && *in.EABHmac != challenge.Unchanged {
		if sealed, err = s.sealOptional(ctx, *in.EABHmac); err != nil {
			return CA{}, err
		}
	}
	if p.RequiresEAB && (in.EABKid == "" || len(sealed) == 0) {
		return CA{}, &ValidationError{"eabKid", p.Name + " requires an EAB key id and HMAC"}
	}
	cfg, err := json.Marshal(in.Config)
	if err != nil {
		return CA{}, err
	}
	row, err := s.q.UpdateCA(ctx, sqlcgen.UpdateCAParams{ID: id, OrgID: orgID, Name: in.Name, Type: in.Type, Config: cfg, Preset: in.Preset,
		DirectoryUrl: in.DirectoryURL, TrustBundlePem: in.TrustBundlePEM, EabKid: in.EABKid, EabHmac: sealed, Resolvers: in.Resolvers})
	if err != nil {
		return CA{}, dbErr(err, "name")
	}
	return caFromRow(row)
}

// GetCA returns one CA of the org.
func (s *Store) GetCA(ctx context.Context, orgID, id uuid.UUID) (CA, error) {
	row, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: id, OrgID: orgID})
	if err != nil {
		return CA{}, notFound(err)
	}
	return caFromRow(row)
}

// ListCAs returns the org's CAs by name.
func (s *Store) ListCAs(ctx context.Context, orgID uuid.UUID) ([]CA, error) {
	rows, err := s.q.ListCAs(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]CA, len(rows))
	for i, r := range rows {
		ca, err := caFromRow(r)
		if err != nil {
			return nil, err
		}
		out[i] = ca
	}
	return out, nil
}

// DeleteCA deletes an unreferenced CA. The row is FOR UPDATE-locked for the
// whole count-then-delete (in one transaction): this blocks a concurrent
// account create, which takes a lock on the same row for its foreign key,
// and it blocks a concurrent org or global issuance-defaults write, which
// takes a FOR KEY SHARE lock on the same row before validating and writing
// (validateDefaultsTx, ValidateGlobalDefaultsTx). Either way the two writers
// serialize instead of racing past each other into a dangling reference; the
// reference checks (CountCAUsers, globalDefaultsReferenceTx) run after the
// lock is held, in the same transaction.
func (s *Store) DeleteCA(ctx context.Context, orgID, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	if _, err := q.LockCA(ctx, sqlcgen.LockCAParams{ID: id, OrgID: orgID}); err != nil {
		return notFound(err)
	}
	n, err := q.CountCAUsers(ctx, id)
	if err != nil {
		return err
	}
	ref, err := s.globalDefaultsReferenceTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if ref {
		n++
	}
	if n > 0 {
		return &InUseError{Users: n}
	}
	if _, err := q.DeleteCA(ctx, sqlcgen.DeleteCAParams{ID: id, OrgID: orgID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CAEAB returns the decrypted EAB material, or nil when the CA has none.
func (s *Store) CAEAB(ctx context.Context, orgID, id uuid.UUID) (*acmesigner.EAB, error) {
	row, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: id, OrgID: orgID})
	if err != nil {
		return nil, notFound(err)
	}
	if len(row.EabHmac) == 0 {
		return nil, nil
	}
	h, err := s.box.Open(ctx, row.EabHmac)
	if err != nil {
		return nil, err
	}
	return &acmesigner.EAB{KID: row.EabKid, HMAC: string(h)}, nil
}

// InsertAccount stores a freshly registered account.
func (s *Store) InsertAccount(ctx context.Context, orgID, caID uuid.UUID, m signer.AccountMaterial) (Account, error) {
	sealed, err := s.box.Seal(ctx, m.KeyPKCS8)
	if err != nil {
		return Account{}, err
	}
	row, err := s.q.CreateAccount(ctx, sqlcgen.CreateAccountParams{OrgID: orgID, CaID: caID, Email: m.Email,
		AccountKey: sealed, RegistrationUri: m.RegistrationURI})
	if err != nil {
		return Account{}, dbErr(err, "email")
	}
	return accountFromRow(row), nil
}

// GetAccount returns one account of the org.
func (s *Store) GetAccount(ctx context.Context, orgID, id uuid.UUID) (Account, error) {
	row, err := s.q.GetAccount(ctx, sqlcgen.GetAccountParams{ID: id, OrgID: orgID})
	if err != nil {
		return Account{}, notFound(err)
	}
	return accountFromRow(row), nil
}

// ListAccounts returns the org's accounts.
func (s *Store) ListAccounts(ctx context.Context, orgID uuid.UUID) ([]Account, error) {
	rows, err := s.q.ListAccounts(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]Account, len(rows))
	for i, r := range rows {
		out[i] = accountFromRow(r)
	}
	return out, nil
}

// DeleteAccount deletes an unreferenced account (the CA-side account is not
// deactivated). The row is FOR UPDATE-locked for the whole count-then-delete
// (in one transaction), which blocks a concurrent org or global
// issuance-defaults write that takes a FOR KEY SHARE lock on the same row
// before validating and writing (validateDefaultsTx, ValidateGlobalDefaultsTx);
// the reference checks (CountAccountUsers, globalDefaultsReferenceTx) run
// after the lock is held, in the same transaction.
func (s *Store) DeleteAccount(ctx context.Context, orgID, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	if _, err := q.LockAccount(ctx, sqlcgen.LockAccountParams{ID: id, OrgID: orgID}); err != nil {
		return notFound(err)
	}
	n, err := q.CountAccountUsers(ctx, id)
	if err != nil {
		return err
	}
	ref, err := s.globalDefaultsReferenceTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if ref {
		n++
	}
	if n > 0 {
		return &InUseError{Users: n}
	}
	if _, err := q.DeleteAccount(ctx, sqlcgen.DeleteAccountParams{ID: id, OrgID: orgID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AccountMaterial returns the account with its decrypted key.
func (s *Store) AccountMaterial(ctx context.Context, orgID, id uuid.UUID) (Account, signer.AccountMaterial, error) {
	row, err := s.q.GetAccount(ctx, sqlcgen.GetAccountParams{ID: id, OrgID: orgID})
	if err != nil {
		return Account{}, signer.AccountMaterial{}, notFound(err)
	}
	key, err := s.box.Open(ctx, row.AccountKey)
	if err != nil {
		return Account{}, signer.AccountMaterial{}, err
	}
	return accountFromRow(row), signer.AccountMaterial{Email: row.Email, KeyPKCS8: key, RegistrationURI: row.RegistrationUri}, nil
}

// createLocalCA generates a fresh root and issuing intermediate, or imports
// an operator-supplied issuing certificate and key, and stores the result:
// config holds the public fields (Shared contract LocalCaConfig plus the
// read-only imported/issuingPem/retired/revoked), secret_cfg holds the
// sealed issuing (and, when generated, root) key, trust_bundle_pem is the
// root PEM (generated) or the last certificate of importPem (import;
// the issuing certificate itself when no chain is given), and
// not_before/not_after are the issuing certificate's own validity.
func (s *Store) createLocalCA(ctx context.Context, orgID uuid.UUID, in CAInput) (CA, error) {
	lcIn, err := parseLocalCAInput(in.Config)
	if err != nil {
		return CA{}, err
	}
	if err := lcIn.validate(); err != nil {
		return CA{}, err
	}
	now := time.Now()

	var (
		cfg         localCAConfig
		sec         localCASecretCfg
		trustBundle string
		notBefore   time.Time
		notAfter    time.Time
	)
	if lcIn.ImportPEM != "" {
		mat, err := localca.Import(lcIn.ImportPEM, lcIn.ImportKeyPEM, lcIn.CRL, now)
		if err != nil {
			if errors.Is(err, localca.ErrCannotSignCRL) {
				return CA{}, &ValidationError{"config.crl", "issuing certificate cannot sign CRLs"}
			}
			return CA{}, &ValidationError{"config.importPem", err.Error()}
		}
		issuingPKCS8, err := x509.MarshalPKCS8PrivateKey(mat.IssuingKey)
		if err != nil {
			return CA{}, err
		}
		cfg = localCAConfig{Subject: lcIn.Subject, KeyType: lcIn.KeyType, RootValidityYears: lcIn.RootValidityYears,
			IssuingValidityYears: lcIn.IssuingValidityYears, MaxLeafDays: lcIn.MaxLeafDays, CRL: lcIn.CRL,
			Imported: true, IssuingPem: pemEncodeCert(mat.Issuing)}
		sec = localCASecretCfg{IssuingKey: issuingPKCS8, ImportKeyPem: lcIn.ImportKeyPEM}
		if mat.Root != nil {
			trustBundle = pemEncodeCert(mat.Root)
		} else {
			trustBundle = pemEncodeCert(mat.Issuing)
		}
		notBefore, notAfter = mat.Issuing.NotBefore, mat.Issuing.NotAfter
	} else {
		mat, rootKeyPKCS8, err := localca.Generate(lcIn.toSignerConfig(), now)
		if err != nil {
			return CA{}, err
		}
		issuingPKCS8, err := x509.MarshalPKCS8PrivateKey(mat.IssuingKey)
		if err != nil {
			return CA{}, err
		}
		cfg = localCAConfig{Subject: lcIn.Subject, KeyType: lcIn.KeyType, RootValidityYears: lcIn.RootValidityYears,
			IssuingValidityYears: lcIn.IssuingValidityYears, MaxLeafDays: lcIn.MaxLeafDays, CRL: lcIn.CRL,
			Imported: false, IssuingPem: pemEncodeCert(mat.Issuing)}
		sec = localCASecretCfg{RootKey: rootKeyPKCS8, IssuingKey: issuingPKCS8}
		trustBundle = pemEncodeCert(mat.Root)
		notBefore, notAfter = mat.Issuing.NotBefore, mat.Issuing.NotAfter
	}

	cfgRaw, err := json.Marshal(cfg)
	if err != nil {
		return CA{}, err
	}
	secretRaw, err := s.sealJSON(ctx, sec)
	if err != nil {
		return CA{}, err
	}
	row, err := s.q.CreateCA(ctx, sqlcgen.CreateCAParams{OrgID: orgID, Name: in.Name, Type: in.Type, Config: cfgRaw,
		SecretCfg: secretRaw, NotBefore: &notBefore, NotAfter: &notAfter, Preset: "", DirectoryUrl: "",
		TrustBundlePem: trustBundle, EabKid: "", EabHmac: nil, Resolvers: in.Resolvers})
	if err != nil {
		return CA{}, dbErr(err, "name")
	}
	return caFromRow(row)
}

// updateLocalCA applies an editable-fields-only update to a localca CA:
// subject, keyType, the validity years and the import fields are
// immutable after create (422); maxLeafDays and crl stay editable (Shared
// contract).
func (s *Store) updateLocalCA(ctx context.Context, orgID, id uuid.UUID, cur sqlcgen.Ca, in CAInput) (CA, error) {
	var curCfg localCAConfig
	if err := json.Unmarshal(cur.Config, &curCfg); err != nil {
		return CA{}, err
	}
	lcIn, err := parseLocalCAInput(in.Config)
	if err != nil {
		return CA{}, err
	}
	if err := lcIn.validate(); err != nil {
		return CA{}, err
	}
	if lcIn.ImportPEM != "" || lcIn.ImportKeyPEM != "" {
		return CA{}, &ValidationError{"config.importPem", "immutable after create"}
	}
	if lcIn.Subject != curCfg.Subject || lcIn.KeyType != curCfg.KeyType ||
		lcIn.RootValidityYears != curCfg.RootValidityYears || lcIn.IssuingValidityYears != curCfg.IssuingValidityYears {
		return CA{}, &ValidationError{"config", "subject, keyType and the validity years are immutable after create"}
	}

	newCfg := curCfg
	newCfg.MaxLeafDays = lcIn.MaxLeafDays
	newCfg.CRL = lcIn.CRL
	cfgRaw, err := json.Marshal(newCfg)
	if err != nil {
		return CA{}, err
	}
	row, err := s.q.UpdateCA(ctx, sqlcgen.UpdateCAParams{ID: id, OrgID: orgID, Name: in.Name, Type: in.Type, Config: cfgRaw,
		Preset: "", DirectoryUrl: "", TrustBundlePem: cur.TrustBundlePem, EabKid: "", EabHmac: nil, Resolvers: in.Resolvers})
	if err != nil {
		return CA{}, dbErr(err, "name")
	}
	return caFromRow(row)
}

// RotateCA generates a fresh issuing certificate under ca's root, retiring
// (never deleting) the current one — sealed until its own certificate's
// notAfter, since a CRL must be signed by its own issuer and leaves already
// issued under it must stay revocable. Returns the updated CA plus the new
// and retired issuer's hex serials, for the caller's audit event. 422 for
// any CA that is not localca, or a localca CA with no held root key (an
// import).
func (s *Store) RotateCA(ctx context.Context, orgID, id uuid.UUID) (ca CA, newIssuerSerial, retiredSerial string, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CA{}, "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	row, err := q.LockCA(ctx, sqlcgen.LockCAParams{ID: id, OrgID: orgID})
	if err != nil {
		return CA{}, "", "", notFound(err)
	}
	if row.Type != CATypeLocalCA {
		return CA{}, "", "", &ValidationError{"id", "rotate is only supported for localca CAs"}
	}
	var cfg localCAConfig
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return CA{}, "", "", err
	}
	var sec localCASecretCfg
	if err := s.openJSON(ctx, row.SecretCfg, &sec); err != nil {
		return CA{}, "", "", err
	}
	if len(sec.RootKey) == 0 {
		return CA{}, "", "", &ValidationError{"id", "no held root key (an imported CA cannot rotate)"}
	}
	root, err := parsePEMCert(row.TrustBundlePem)
	if err != nil {
		return CA{}, "", "", err
	}
	oldIssuing, err := parsePEMCert(cfg.IssuingPem)
	if err != nil {
		return CA{}, "", "", err
	}

	rootKeyCopy := append([]byte(nil), sec.RootKey...)
	newMat, err := localca.Rotate(root, rootKeyCopy, cfg.toSignerConfig(), time.Now())
	if err != nil {
		return CA{}, "", "", err
	}
	newIssuingPKCS8, err := x509.MarshalPKCS8PrivateKey(newMat.IssuingKey)
	if err != nil {
		return CA{}, "", "", err
	}

	now := time.Now()
	retiredSerial = oldIssuing.SerialNumber.Text(16)
	cfg.Retired = append(cfg.Retired, retiredIssuer{PEM: pemEncodeCert(oldIssuing), NotAfter: oldIssuing.NotAfter, Serial: retiredSerial})
	sec.Retired = append(sec.Retired, retiredSecretKey{Serial: retiredSerial, Key: sec.IssuingKey, NotAfter: oldIssuing.NotAfter})
	cfg.Retired = purgeExpiredRetiredPublic(cfg.Retired, now)
	sec.Retired = purgeExpiredRetiredSecret(sec.Retired, now)

	newIssuerSerial = newMat.Issuing.SerialNumber.Text(16)
	cfg.IssuingPem = pemEncodeCert(newMat.Issuing)
	sec.IssuingKey = newIssuingPKCS8

	cfgRaw, err := json.Marshal(cfg)
	if err != nil {
		return CA{}, "", "", err
	}
	secretRaw, err := s.sealJSON(ctx, sec)
	if err != nil {
		return CA{}, "", "", err
	}
	newRow, err := q.UpdateCACrypto(ctx, sqlcgen.UpdateCACryptoParams{ID: id, OrgID: orgID, Config: cfgRaw, SecretCfg: secretRaw,
		NotBefore: &newMat.Issuing.NotBefore, NotAfter: &newMat.Issuing.NotAfter, CrlNumber: row.CrlNumber})
	if err != nil {
		return CA{}, "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return CA{}, "", "", err
	}
	ca, err = caFromRow(newRow)
	return ca, newIssuerSerial, retiredSerial, err
}

// purgeExpiredRetiredPublic drops retired issuer entries past their own
// notAfter (ADR 0015: a retired key is kept only until its certificate
// expires, purged at the next rotate or CRL build after that — this runs
// at the next rotate).
func purgeExpiredRetiredPublic(in []retiredIssuer, now time.Time) []retiredIssuer {
	out := in[:0:0]
	for _, r := range in {
		if r.NotAfter.After(now) {
			out = append(out, r)
		}
	}
	return out
}

func purgeExpiredRetiredSecret(in []retiredSecretKey, now time.Time) []retiredSecretKey {
	out := in[:0:0]
	for _, r := range in {
		if r.NotAfter.After(now) {
			out = append(out, r)
		}
	}
	return out
}

// RevokeVersion revokes one issued private-CA certificate version: it
// locks the version and its CA (Locking constraint), checks the version is
// an issued (not imported/uploaded) leaf of a private CA, builds a Signer
// over the issuer that actually signed it (current or, per Task 6's
// carry-forward, a retired one found by the leaf's AuthorityKeyId), and
// records the revocation both on the version (revoked_at) and the CA
// (config.revoked, crl_number++, via localca's Recorder). 409 if already
// revoked; 422 for an ACME CA, a non-issued version, or (until Task 9)
// vaultpki.
func (s *Store) RevokeVersion(ctx context.Context, orgID, certID, versionID uuid.UUID, reason int, baseURL func(context.Context) string) (certstore.Version, error) {
	if _, err := s.q.GetCertificate(ctx, sqlcgen.GetCertificateParams{ID: certID, OrgID: orgID}); err != nil {
		return certstore.Version{}, notFound(err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return certstore.Version{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	vrow, err := q.LockCertificateVersionForUpdate(ctx, sqlcgen.LockCertificateVersionForUpdateParams{ID: versionID, CertID: certID})
	if err != nil {
		return certstore.Version{}, notFound(err)
	}
	if vrow.RevokedAt != nil {
		return certstore.Version{}, &ConflictError{Msg: "version is already revoked"}
	}
	if vrow.Source != "issued" || vrow.CaID == nil {
		return certstore.Version{}, &ValidationError{"versionId", "version was not issued by CertForge"}
	}
	caRow, err := q.LockCA(ctx, sqlcgen.LockCAParams{ID: *vrow.CaID, OrgID: orgID})
	if err != nil {
		return certstore.Version{}, notFound(err)
	}
	if caRow.Type == CATypeACME {
		return certstore.Version{}, &ValidationError{"versionId", "not supported for ACME CAs yet"}
	}
	if caRow.Type != CATypeLocalCA {
		return certstore.Version{}, &ValidationError{"versionId", "not supported for this CA kind yet"}
	}
	leaf, err := x509.ParseCertificate(vrow.LeafDer)
	if err != nil {
		return certstore.Version{}, err
	}
	var cfg localCAConfig
	if err := json.Unmarshal(caRow.Config, &cfg); err != nil {
		return certstore.Version{}, err
	}
	issuerSerial, ok := issuerSerialForLeaf(cfg, leaf)
	if !ok {
		return certstore.Version{}, &ValidationError{"versionId", "issuing certificate no longer available"}
	}
	sig, err := s.localCASignerFromRow(ctx, q, caRow, baseURL(ctx), issuerSerial)
	if err != nil {
		return certstore.Version{}, err
	}
	if err := sig.Revoke(ctx, leaf, reason); err != nil {
		return certstore.Version{}, err
	}

	now := time.Now()
	updated, err := q.SetCertificateVersionRevoked(ctx, sqlcgen.SetCertificateVersionRevokedParams{ID: versionID, CertID: certID, RevokedAt: &now})
	if err != nil {
		return certstore.Version{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return certstore.Version{}, err
	}
	return certstore.Version{ID: updated.ID, CertID: updated.CertID, Serial: updated.Serial, NotBefore: updated.NotBefore,
		NotAfter: updated.NotAfter, SHA256: updated.Sha256Fp, KeyType: updated.KeyType, Source: updated.Source,
		HasKey: updated.HasKey, CAID: updated.CaID, RevokedAt: updated.RevokedAt, CreatedAt: updated.CreatedAt}, nil
}
