package issuance

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

// Certificate statuses.
const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusFailed  = "failed"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

// Certificate is a managed certificate definition.
type Certificate struct {
	ID, OrgID            uuid.UUID
	Name, CommonName     string
	SANs                 []string
	Rules                []challenge.RuleSpec
	Overrides            Defaults
	Status               string
	CurrentVersionID     *uuid.UUID
	NextRenewAt          *time.Time
	FailureCount         int
	LastError            string
	CreatedAt, UpdatedAt time.Time
}

// Names returns the common name followed by the SANs.
func (c Certificate) Names() []string { return append([]string{c.CommonName}, c.SANs...) }

// CertInput creates or replaces a certificate definition.
type CertInput struct {
	Name, CommonName string
	SANs             []string
	Rules            []challenge.RuleSpec
	Overrides        Defaults
}

func certFromRow(r sqlcgen.Certificate) (Certificate, error) {
	c := Certificate{ID: r.ID, OrgID: r.OrgID, Name: r.Name, CommonName: r.CommonName, SANs: r.Sans,
		Status: r.Status, CurrentVersionID: r.CurrentVersionID, NextRenewAt: r.NextRenewAt,
		FailureCount: int(r.FailureCount), LastError: r.LastError, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if err := json.Unmarshal(r.VerificationRules, &c.Rules); err != nil {
		return c, err
	}
	err := json.Unmarshal(r.Overrides, &c.Overrides)
	return c, err
}

// GlobalDefaults reads the global settings section (zero when never saved).
func (s *Store) GlobalDefaults(ctx context.Context) (Defaults, error) {
	var d Defaults
	if s.global == nil {
		return d, nil
	}
	err := s.global.Get(ctx, settings.SectionKey(SettingsKey), &d)
	if errors.Is(err, settings.ErrNotFound) {
		return Defaults{}, nil
	}
	return d, err
}

// OrgDefaults returns the org level (zero Defaults when unset).
func (s *Store) OrgDefaults(ctx context.Context, orgID uuid.UUID) (Defaults, error) {
	var d Defaults
	b, err := s.q.GetOrgIssuanceDefaults(ctx, orgID)
	if err != nil {
		if errors.Is(notFound(err), ErrNotFound) {
			return d, nil
		}
		return d, err
	}
	err = json.Unmarshal(b, &d)
	return d, err
}

// PutOrgDefaults validates and replaces the org level. Runs inside one
// transaction: validateDefaultsTx takes a FOR KEY SHARE lock on any
// referenced CA or account before checking it exists, so a concurrent
// DeleteCA/DeleteAccount (which takes FOR UPDATE on the same row) blocks
// until this transaction ends, instead of the two racing past each other
// into a dangling reference.
func (s *Store) PutOrgDefaults(ctx context.Context, orgID uuid.UUID, d Defaults) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	if err := s.validateDefaultsTx(ctx, q, orgID, d); err != nil {
		return err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if err := q.UpsertOrgIssuanceDefaults(ctx, sqlcgen.UpsertOrgIssuanceDefaultsParams{OrgID: orgID, Config: b}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// EffectiveOrg resolves global and org levels.
func (s *Store) EffectiveOrg(ctx context.Context, orgID uuid.UUID) (Effective, error) {
	return s.effective(ctx, orgID, Defaults{})
}

// EffectiveFor resolves all three levels for a certificate.
func (s *Store) EffectiveFor(ctx context.Context, c Certificate) (Effective, error) {
	return s.effective(ctx, c.OrgID, c.Overrides)
}

func (s *Store) effective(ctx context.Context, orgID uuid.UUID, cert Defaults) (Effective, error) {
	g, err := s.GlobalDefaults(ctx)
	if err != nil {
		return Effective{}, err
	}
	o, err := s.OrgDefaults(ctx, orgID)
	if err != nil {
		return Effective{}, err
	}
	return Resolve(g, o, cert), nil
}

// globalDefaultsReference reports whether the global issuance_defaults
// section still references id as caId, accountId, or a rule's
// dnsCredentialId (P34: Count*Users only sees org-scoped rows, so a
// globally referenced CA, account or credential must be checked separately
// before it can be deleted).
func (s *Store) globalDefaultsReference(ctx context.Context, id uuid.UUID) (bool, error) {
	g, err := s.GlobalDefaults(ctx)
	if err != nil {
		return false, err
	}
	return defaultsReference(g, id), nil
}

// txGlobalSettings is implemented by *settings.Store (its GetTx);
// globalDefaultsReferenceTx uses it when s.global supports it, so the read
// runs inside the caller's own transaction instead of the settings store's
// own pool-bound queries. Test doubles that only implement GlobalSettings's
// plain Get fall back to that.
type txGlobalSettings interface {
	GetTx(ctx context.Context, tx pgx.Tx, key string, out any) error
}

// globalDefaultsReferenceTx is globalDefaultsReference read through tx (when
// s.global supports it) instead of the settings store's own pool-bound
// queries, so DeleteCA/DeleteAccount's decision is made entirely from reads
// taken after their FOR UPDATE lock is held, in the same transaction as the
// count and the delete.
func (s *Store) globalDefaultsReferenceTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	if s.global == nil {
		return false, nil
	}
	key := settings.SectionKey(SettingsKey)
	var g Defaults
	var err error
	if tg, ok := s.global.(txGlobalSettings); ok {
		err = tg.GetTx(ctx, tx, key, &g)
	} else {
		err = s.global.Get(ctx, key, &g)
	}
	if errors.Is(err, settings.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return defaultsReference(g, id), nil
}

// defaultsReference reports whether g references id as caId, accountId, or
// a rule's dnsCredentialId.
func defaultsReference(g Defaults, id uuid.UUID) bool {
	if g.CAID != nil && *g.CAID == id {
		return true
	}
	if g.AccountID != nil && *g.AccountID == id {
		return true
	}
	if g.VerificationRules != nil {
		for _, r := range *g.VerificationRules {
			if r.DNSCredentialID != nil && *r.DNSCredentialID == id {
				return true
			}
		}
	}
	return false
}

// validateDefaultsShape checks the fields of a Defaults value that do not
// need a database lookup (used at every level: global, org and certificate
// overrides).
func validateDefaultsShape(d Defaults) error {
	if d.KeyType != nil && !d.KeyType.Valid() {
		return &ValidationError{"keyType", "must be one of rsa2048, rsa3072, rsa4096, ec256, ec384"}
	}
	if p := d.RenewPolicy; p != nil {
		switch {
		case p.Mode == RenewDays && (p.Value < 1 || p.Value > 365):
			return &ValidationError{"renewPolicy.value", "days must be 1..365"}
		case p.Mode == RenewPercent && (p.Value < 1 || p.Value > 99):
			return &ValidationError{"renewPolicy.value", "percent must be 1..99"}
		case p.Mode != RenewDays && p.Mode != RenewPercent:
			return &ValidationError{"renewPolicy.mode", "must be days or percent"}
		}
	}
	if d.PropagationSeconds != nil && (*d.PropagationSeconds < 0 || *d.PropagationSeconds > 3600) {
		return &ValidationError{"propagationSeconds", "must be 0..3600"}
	}
	if d.Resolvers != nil {
		if err := validateResolvers("resolvers", *d.Resolvers); err != nil {
			return err
		}
	}
	if d.VerificationRules != nil {
		for _, r := range *d.VerificationRules {
			if err := r.Validate(); err != nil {
				return &ValidationError{"verificationRules", err.Error()}
			}
		}
	}
	return nil
}

// validateDefaultsTx validates an org-level Defaults value (org defaults, a
// certificate's overrides, or the global settings section): the shape, plus
// that any referenced caId or accountId names a row of this org (P34),
// taking a FOR KEY SHARE lock on it first so DeleteCA/DeleteAccount's FOR
// UPDATE lock on the same row blocks until this transaction ends. Used by
// every writer (PutOrgDefaults, certificate create/update) that must be
// safe against a concurrent delete racing the write, not just against a
// delete that has already committed.
func (s *Store) validateDefaultsTx(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, d Defaults) error {
	if err := validateDefaultsShape(d); err != nil {
		return err
	}
	if d.CAID != nil {
		if _, err := q.LockCAKeyShare(ctx, *d.CAID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"caId", "no such CA in this org"}
			}
			return err
		}
		if _, err := q.GetCA(ctx, sqlcgen.GetCAParams{ID: *d.CAID, OrgID: orgID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"caId", "no such CA in this org"}
			}
			return err
		}
	}
	if d.AccountID != nil {
		if _, err := q.LockAccountKeyShare(ctx, *d.AccountID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"accountId", "no such ACME account in this org"}
			}
			return err
		}
		a, err := q.GetAccount(ctx, sqlcgen.GetAccountParams{ID: *d.AccountID, OrgID: orgID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"accountId", "no such ACME account in this org"}
			}
			return err
		}
		if d.CAID != nil && a.CaID != *d.CAID {
			return &ValidationError{"accountId", "account belongs to a different CA"}
		}
	}
	if d.VerificationRules != nil {
		return s.validateRulesOrgTx(ctx, q, orgID, *d.VerificationRules)
	}
	return nil
}

// ValidateGlobalDefaults validates the global issuance_defaults settings
// section: the shape, plus that any referenced caId, accountId or rule
// dnsCredentialId names a row that exists (P34). The global section is not
// org-scoped, so this checks existence only, not which org owns the row;
// resolving a global default to an org (so it applies only in that org) is
// Phase 2 cross-org work. Callers (the settings write path) should run this
// before storing the section.
func (s *Store) ValidateGlobalDefaults(ctx context.Context, d Defaults) error {
	if err := validateDefaultsShape(d); err != nil {
		return err
	}
	if d.CAID != nil {
		if _, err := s.q.GetCAByID(ctx, *d.CAID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"caId", "no such CA"}
			}
			return err
		}
	}
	if d.AccountID != nil {
		a, err := s.q.GetAccountByID(ctx, *d.AccountID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"accountId", "no such ACME account"}
			}
			return err
		}
		if d.CAID != nil && a.CaID != *d.CAID {
			return &ValidationError{"accountId", "account belongs to a different CA"}
		}
	}
	if d.VerificationRules != nil {
		for _, r := range *d.VerificationRules {
			if r.DNSCredentialID == nil {
				continue
			}
			ok, err := s.q.DNSCredentialExists(ctx, *r.DNSCredentialID)
			if err != nil {
				return err
			}
			if !ok {
				return &ValidationError{"verificationRules", "rule " + r.Match + ": no such DNS credential"}
			}
		}
	}
	return nil
}

// ValidateGlobalDefaultsTx is ValidateGlobalDefaults run with tx-scoped
// queries, taking a FOR KEY SHARE lock on any referenced CA or account
// first so DeleteCA/DeleteAccount's FOR UPDATE lock on the same row blocks
// until this transaction ends. The settings write path (PUT
// /settings/issuance_defaults) uses this, not ValidateGlobalDefaults, and
// writes the section through the same transaction, so the two can't
// interleave into a dangling reference.
func (s *Store) ValidateGlobalDefaultsTx(ctx context.Context, tx pgx.Tx, d Defaults) error {
	if err := validateDefaultsShape(d); err != nil {
		return err
	}
	q := s.q.WithTx(tx)
	if d.CAID != nil {
		if _, err := q.LockCAKeyShare(ctx, *d.CAID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"caId", "no such CA"}
			}
			return err
		}
	}
	if d.AccountID != nil {
		if _, err := q.LockAccountKeyShare(ctx, *d.AccountID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"accountId", "no such ACME account"}
			}
			return err
		}
		a, err := q.GetAccountByID(ctx, *d.AccountID)
		if err != nil {
			return err
		}
		if d.CAID != nil && a.CaID != *d.CAID {
			return &ValidationError{"accountId", "account belongs to a different CA"}
		}
	}
	if d.VerificationRules != nil {
		for _, r := range *d.VerificationRules {
			if r.DNSCredentialID == nil {
				continue
			}
			// LockDNSCredentialKeyShare doubles as the existence check (its
			// FOR KEY SHARE SELECT returns pgx.ErrNoRows when the credential
			// is gone), same as the CAID check above; it also blocks a
			// concurrent DeleteDNSCredential until this transaction ends.
			if _, err := q.LockDNSCredentialKeyShare(ctx, *r.DNSCredentialID); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return &ValidationError{"verificationRules", "rule " + r.Match + ": no such DNS credential"}
				}
				return err
			}
		}
	}
	return nil
}

// validateRulesOrgTx checks that every rule's dnsCredentialId belongs to
// orgID, taking a FOR KEY SHARE lock on any referenced credential first so
// DeleteDNSCredential's FOR UPDATE lock on the same row blocks until this
// transaction ends; see validateDefaultsTx.
func (s *Store) validateRulesOrgTx(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, rules []challenge.RuleSpec) error {
	for _, r := range rules {
		if r.DNSCredentialID == nil {
			continue
		}
		if _, err := q.LockDNSCredentialKeyShare(ctx, *r.DNSCredentialID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"verificationRules", "rule " + r.Match + ": no such DNS credential in this org"}
			}
			return err
		}
		if _, err := q.GetDNSCredential(ctx, sqlcgen.GetDNSCredentialParams{ID: *r.DNSCredentialID, OrgID: orgID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &ValidationError{"verificationRules", "rule " + r.Match + ": no such DNS credential in this org"}
			}
			return err
		}
	}
	return nil
}

// prepareCertTx validates and normalizes in using tx-scoped queries: the
// shape, plus a FOR KEY SHARE lock and existence check on every CA, account
// or DNS credential it references (validateDefaultsTx, validateRulesOrgTx),
// so a concurrent delete of one of those rows blocks until the certificate
// write's own transaction ends instead of racing it into a dangling
// reference (mirrors PutOrgDefaults; see validateDefaultsTx).
func (s *Store) prepareCertTx(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, in *CertInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return &ValidationError{"name", "required"}
	}
	names, err := NormalizeNames(in.CommonName, in.SANs)
	if err != nil {
		return &ValidationError{"sans", err.Error()}
	}
	in.CommonName, in.SANs = names[0], names[1:]
	if in.Rules == nil {
		in.Rules = []challenge.RuleSpec{}
	}
	for _, r := range in.Rules {
		if err := r.Validate(); err != nil {
			return &ValidationError{"verificationRules", err.Error()}
		}
	}
	if err := s.validateRulesOrgTx(ctx, q, orgID, in.Rules); err != nil {
		return err
	}
	return s.validateDefaultsTx(ctx, q, orgID, in.Overrides)
}

// CreateCertificate stores a definition, due for issuance now. Runs inside
// one transaction; see prepareCertTx.
func (s *Store) CreateCertificate(ctx context.Context, orgID uuid.UUID, in CertInput) (Certificate, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Certificate{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	if err := s.prepareCertTx(ctx, q, orgID, &in); err != nil {
		return Certificate{}, err
	}
	rules, err := json.Marshal(in.Rules)
	if err != nil {
		return Certificate{}, err
	}
	over, err := json.Marshal(in.Overrides)
	if err != nil {
		return Certificate{}, err
	}
	row, err := q.CreateCertificate(ctx, sqlcgen.CreateCertificateParams{OrgID: orgID, Name: in.Name,
		CommonName: in.CommonName, Sans: in.SANs, VerificationRules: rules, Overrides: over})
	if err != nil {
		return Certificate{}, dbErr(err, "name")
	}
	c, err := certFromRow(row)
	if err != nil {
		return Certificate{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, err
	}
	return c, nil
}

// UpdateCertificate replaces a definition. reissue reports that the names
// changed, which makes the certificate due now. Runs inside one
// transaction; see prepareCertTx.
func (s *Store) UpdateCertificate(ctx context.Context, orgID, id uuid.UUID, in CertInput) (c Certificate, reissue bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Certificate{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	curRow, err := q.GetCertificate(ctx, sqlcgen.GetCertificateParams{ID: id, OrgID: orgID})
	if err != nil {
		return Certificate{}, false, notFound(err)
	}
	cur, err := certFromRow(curRow)
	if err != nil {
		return Certificate{}, false, err
	}
	if err := s.prepareCertTx(ctx, q, orgID, &in); err != nil {
		return Certificate{}, false, err
	}
	reissue = !slices.Equal(cur.Names(), append([]string{in.CommonName}, in.SANs...))
	rules, err := json.Marshal(in.Rules)
	if err != nil {
		return Certificate{}, false, err
	}
	over, err := json.Marshal(in.Overrides)
	if err != nil {
		return Certificate{}, false, err
	}
	row, err := q.UpdateCertificate(ctx, sqlcgen.UpdateCertificateParams{ID: id, OrgID: orgID, Name: in.Name,
		CommonName: in.CommonName, Sans: in.SANs, VerificationRules: rules, Overrides: over, Reissue: reissue})
	if err != nil {
		return Certificate{}, false, dbErr(err, "name")
	}
	c, err = certFromRow(row)
	if err != nil {
		return Certificate{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, false, err
	}
	return c, reissue, nil
}

// GetCertificate returns one certificate of the org.
func (s *Store) GetCertificate(ctx context.Context, orgID, id uuid.UUID) (Certificate, error) {
	row, err := s.q.GetCertificate(ctx, sqlcgen.GetCertificateParams{ID: id, OrgID: orgID})
	if err != nil {
		return Certificate{}, notFound(err)
	}
	return certFromRow(row)
}

// CertificateByID is for workers, which are not org-scoped.
func (s *Store) CertificateByID(ctx context.Context, id uuid.UUID) (Certificate, error) {
	row, err := s.q.GetCertificateByID(ctx, id)
	if err != nil {
		return Certificate{}, notFound(err)
	}
	return certFromRow(row)
}

// ListCertificates returns the org's certificates by name.
func (s *Store) ListCertificates(ctx context.Context, orgID uuid.UUID) ([]Certificate, error) {
	rows, err := s.q.ListCertificates(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]Certificate, 0, len(rows))
	for _, r := range rows {
		c, err := certFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// DeleteCertificate deletes a certificate and all its versions and attempts.
func (s *Store) DeleteCertificate(ctx context.Context, orgID, id uuid.UUID) error {
	n, err := s.q.DeleteCertificate(ctx, sqlcgen.DeleteCertificateParams{ID: id, OrgID: orgID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DueCertificateIDs returns certificates whose next_renew_at has passed.
func (s *Store) DueCertificateIDs(ctx context.Context, limit int) ([]uuid.UUID, error) {
	return s.q.ListDueCertificateIDs(ctx, int32(limit))
}

// MarkExpired flips active/failed certificates whose current version expired.
func (s *Store) MarkExpired(ctx context.Context) (int64, error) {
	return s.q.MarkExpiredCertificates(ctx)
}

// MarkFailed records a failed attempt on the certificate.
func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, status string, failures int, lastErr string, next time.Time) error {
	return s.q.MarkCertificateFailed(ctx, sqlcgen.MarkCertificateFailedParams{ID: id, Status: status,
		FailureCount: int32(failures), LastError: lastErr, NextRenewAt: &next})
}
