package issuance

import (
	"context"
	"crypto/x509"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
)

// CA is an ACME directory. Shared is reserved for Phase 2 global CAs.
type CA struct {
	ID, OrgID                                          uuid.UUID
	Name, Preset, DirectoryURL, TrustBundlePEM, EABKid string
	HasEAB                                             bool
	Resolvers                                          []string
	Shared                                             bool
	CreatedAt, UpdatedAt                               time.Time
}

// CAInput creates or replaces a CA. EABHmac: on create nil/"" = none; on
// update nil or challenge.Unchanged keeps the stored value, "" clears it.
type CAInput struct {
	Name, Preset, DirectoryURL, TrustBundlePEM, EABKid string
	EABHmac                                            *string
	Resolvers                                          []string
}

// Account is a registered ACME account (key never leaves the store).
type Account struct {
	ID, OrgID, CAID uuid.UUID
	Email, Status   string
	RegistrationURI string
	CreatedAt       time.Time
}

func caFromRow(r sqlcgen.Ca) CA {
	return CA{ID: r.ID, OrgID: r.OrgID, Name: r.Name, Preset: r.Preset, DirectoryURL: r.DirectoryUrl,
		TrustBundlePEM: r.TrustBundlePem, EABKid: r.EabKid, HasEAB: len(r.EabHmac) > 0,
		Resolvers: r.Resolvers, Shared: r.Shared, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
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
	hmac := ""
	if in.EABHmac != nil {
		hmac = *in.EABHmac
	}
	if p.RequiresEAB && (in.EABKid == "" || hmac == "") {
		return CA{}, &ValidationError{"eabKid", p.Name + " requires an EAB key id and HMAC"}
	}
	sealed, err := s.sealOptional(ctx, hmac)
	if err != nil {
		return CA{}, err
	}
	row, err := s.q.CreateCA(ctx, sqlcgen.CreateCAParams{OrgID: orgID, Name: in.Name, Preset: in.Preset,
		DirectoryUrl: in.DirectoryURL, TrustBundlePem: in.TrustBundlePEM, EabKid: in.EABKid, EabHmac: sealed, Resolvers: in.Resolvers})
	if err != nil {
		return CA{}, dbErr(err, "name")
	}
	return caFromRow(row), nil
}

// UpdateCA replaces a CA's fields.
func (s *Store) UpdateCA(ctx context.Context, orgID, id uuid.UUID, in CAInput) (CA, error) {
	cur, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: id, OrgID: orgID})
	if err != nil {
		return CA{}, notFound(err)
	}
	p, err := in.normalize()
	if err != nil {
		return CA{}, err
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
	row, err := s.q.UpdateCA(ctx, sqlcgen.UpdateCAParams{ID: id, OrgID: orgID, Name: in.Name, Preset: in.Preset,
		DirectoryUrl: in.DirectoryURL, TrustBundlePem: in.TrustBundlePEM, EabKid: in.EABKid, EabHmac: sealed, Resolvers: in.Resolvers})
	if err != nil {
		return CA{}, dbErr(err, "name")
	}
	return caFromRow(row), nil
}

// GetCA returns one CA of the org.
func (s *Store) GetCA(ctx context.Context, orgID, id uuid.UUID) (CA, error) {
	row, err := s.q.GetCA(ctx, sqlcgen.GetCAParams{ID: id, OrgID: orgID})
	if err != nil {
		return CA{}, notFound(err)
	}
	return caFromRow(row), nil
}

// ListCAs returns the org's CAs by name.
func (s *Store) ListCAs(ctx context.Context, orgID uuid.UUID) ([]CA, error) {
	rows, err := s.q.ListCAs(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]CA, len(rows))
	for i, r := range rows {
		out[i] = caFromRow(r)
	}
	return out, nil
}

// DeleteCA deletes an unreferenced CA.
func (s *Store) DeleteCA(ctx context.Context, orgID, id uuid.UUID) error {
	if _, err := s.GetCA(ctx, orgID, id); err != nil {
		return err
	}
	n, err := s.q.CountCAUsers(ctx, id)
	if err != nil {
		return err
	}
	ref, err := s.globalDefaultsReference(ctx, id)
	if err != nil {
		return err
	}
	if ref {
		n++
	}
	if n > 0 {
		return &InUseError{Users: n}
	}
	_, err = s.q.DeleteCA(ctx, sqlcgen.DeleteCAParams{ID: id, OrgID: orgID})
	return err
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
// deactivated).
func (s *Store) DeleteAccount(ctx context.Context, orgID, id uuid.UUID) error {
	if _, err := s.GetAccount(ctx, orgID, id); err != nil {
		return err
	}
	n, err := s.q.CountAccountUsers(ctx, id)
	if err != nil {
		return err
	}
	ref, err := s.globalDefaultsReference(ctx, id)
	if err != nil {
		return err
	}
	if ref {
		n++
	}
	if n > 0 {
		return &InUseError{Users: n}
	}
	_, err = s.q.DeleteAccount(ctx, sqlcgen.DeleteAccountParams{ID: id, OrgID: orgID})
	return err
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
