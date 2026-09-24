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

// PutOrgDefaults validates and replaces the org level.
func (s *Store) PutOrgDefaults(ctx context.Context, orgID uuid.UUID, d Defaults) error {
	if err := s.validateDefaults(ctx, orgID, d); err != nil {
		return err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return s.q.UpsertOrgIssuanceDefaults(ctx, sqlcgen.UpsertOrgIssuanceDefaultsParams{OrgID: orgID, Config: b})
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
	if g.CAID != nil && *g.CAID == id {
		return true, nil
	}
	if g.AccountID != nil && *g.AccountID == id {
		return true, nil
	}
	if g.VerificationRules != nil {
		for _, r := range *g.VerificationRules {
			if r.DNSCredentialID != nil && *r.DNSCredentialID == id {
				return true, nil
			}
		}
	}
	return false, nil
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

// validateDefaults validates an org-level Defaults value (org defaults or a
// certificate's overrides): the shape, plus that any referenced caId,
// accountId or rule dnsCredentialId names a row of this org (P34).
func (s *Store) validateDefaults(ctx context.Context, orgID uuid.UUID, d Defaults) error {
	if err := validateDefaultsShape(d); err != nil {
		return err
	}
	if d.CAID != nil {
		if _, err := s.GetCA(ctx, orgID, *d.CAID); err != nil {
			if errors.Is(err, ErrNotFound) {
				return &ValidationError{"caId", "no such CA in this org"}
			}
			return err
		}
	}
	if d.AccountID != nil {
		a, err := s.GetAccount(ctx, orgID, *d.AccountID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return &ValidationError{"accountId", "no such ACME account in this org"}
			}
			return err
		}
		if d.CAID != nil && a.CAID != *d.CAID {
			return &ValidationError{"accountId", "account belongs to a different CA"}
		}
	}
	if d.VerificationRules != nil {
		return s.validateRulesOrg(ctx, orgID, *d.VerificationRules)
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

// validateRulesOrg checks that every rule's dnsCredentialId belongs to orgID.
func (s *Store) validateRulesOrg(ctx context.Context, orgID uuid.UUID, rules []challenge.RuleSpec) error {
	for _, r := range rules {
		if r.DNSCredentialID != nil {
			if _, err := s.q.GetDNSCredential(ctx, sqlcgen.GetDNSCredentialParams{ID: *r.DNSCredentialID, OrgID: orgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return &ValidationError{"verificationRules", "rule " + r.Match + ": no such DNS credential in this org"}
				}
				return err
			}
		}
	}
	return nil
}

func (s *Store) prepareCert(ctx context.Context, orgID uuid.UUID, in *CertInput) error {
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
	if err := s.validateRulesOrg(ctx, orgID, in.Rules); err != nil {
		return err
	}
	return s.validateDefaults(ctx, orgID, in.Overrides)
}

// CreateCertificate stores a definition, due for issuance now.
func (s *Store) CreateCertificate(ctx context.Context, orgID uuid.UUID, in CertInput) (Certificate, error) {
	if err := s.prepareCert(ctx, orgID, &in); err != nil {
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
	row, err := s.q.CreateCertificate(ctx, sqlcgen.CreateCertificateParams{OrgID: orgID, Name: in.Name,
		CommonName: in.CommonName, Sans: in.SANs, VerificationRules: rules, Overrides: over})
	if err != nil {
		return Certificate{}, dbErr(err, "name")
	}
	return certFromRow(row)
}

// UpdateCertificate replaces a definition. reissue reports that the names
// changed, which makes the certificate due now.
func (s *Store) UpdateCertificate(ctx context.Context, orgID, id uuid.UUID, in CertInput) (c Certificate, reissue bool, err error) {
	cur, err := s.GetCertificate(ctx, orgID, id)
	if err != nil {
		return Certificate{}, false, err
	}
	if err := s.prepareCert(ctx, orgID, &in); err != nil {
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
	row, err := s.q.UpdateCertificate(ctx, sqlcgen.UpdateCertificateParams{ID: id, OrgID: orgID, Name: in.Name,
		CommonName: in.CommonName, Sans: in.SANs, VerificationRules: rules, Overrides: over, Reissue: reissue})
	if err != nil {
		return Certificate{}, false, dbErr(err, "name")
	}
	c, err = certFromRow(row)
	return c, reissue, err
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
