package issuance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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

// Certificate is a managed certificate definition. Managed is false for an
// imported or uploaded certificate: CertForge stores and can deploy it, but
// never renews it (NextRenewAt is always nil), and renew/most edits are
// refused.
type Certificate struct {
	ID, OrgID            uuid.UUID
	Name, CommonName     string
	SANs                 []string
	Rules                []challenge.RuleSpec
	Overrides            Defaults
	Status               string
	Managed              bool
	CurrentVersionID     *uuid.UUID
	NextRenewAt          *time.Time
	FailureCount         int
	LastError            string
	CreatedAt, UpdatedAt time.Time

	// AriWindowStart/End/CheckedAt cache the CA's ACME Renewal Information
	// window for the current version (Task 12); all three are nil until a
	// poll has succeeded. AriRetryAfter is the earliest time the next poll
	// may run (ARIPollWorker) and is not exposed on the API certificate.
	AriWindowStart, AriWindowEnd, AriCheckedAt, AriRetryAfter *time.Time
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
		Status: r.Status, Managed: r.Managed, CurrentVersionID: r.CurrentVersionID, NextRenewAt: r.NextRenewAt,
		FailureCount: int(r.FailureCount), LastError: r.LastError, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		AriWindowStart: r.AriWindowStart, AriWindowEnd: r.AriWindowEnd, AriCheckedAt: r.AriCheckedAt, AriRetryAfter: r.AriRetryAfter}
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
// dnsCredentialId/clientId names a row that exists (P34) — a rule's
// clientId is treated exactly like its dnsCredentialId, plus (unless the
// rule is http-01 with its own webroot) that the client reports the rule's
// method capability. The global section is not org-scoped, so this checks
// existence only, not which org owns the row; resolving a global default to
// an org (so it applies only in that org) is Phase 2 cross-org work.
// Callers (the settings write path) should run this before storing the
// section.
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
		for _, r := range *d.VerificationRules {
			if r.ClientID == nil {
				continue
			}
			c, err := s.q.GetClientByID(ctx, *r.ClientID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return &ValidationError{"verificationRules", "rule " + r.Match + ": no such client"}
				}
				return err
			}
			if err := checkRuleClientCapability(r, c); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateGlobalDefaultsTx is ValidateGlobalDefaults run with tx-scoped
// queries, taking a FOR KEY SHARE lock on any referenced CA, account or
// client first so DeleteCA/DeleteAccount/DeleteClient's FOR UPDATE lock on
// the same row blocks until this transaction ends. The settings write path
// (PUT /settings/issuance_defaults) uses this, not ValidateGlobalDefaults,
// and writes the section through the same transaction, so the two can't
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
		clients, err := lockRuleClientsInIDOrder(ctx, q, uuid.Nil, false, *d.VerificationRules)
		if err != nil {
			return err
		}
		for _, r := range *d.VerificationRules {
			if r.ClientID == nil {
				continue
			}
			if err := checkRuleClientCapability(r, clients[*r.ClientID]); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateRulesOrgTx checks that every rule's dnsCredentialId or clientId
// belongs to orgID, taking a FOR KEY SHARE lock on any referenced
// credential or client first so a concurrent DeleteDNSCredential/
// DeleteClient's FOR UPDATE lock on the same row blocks until this
// transaction ends; see validateDefaultsTx. Called for both a certificate's
// own rules and org-level default rules (PutOrgDefaults), so a rule's
// clientId is validated identically at either level.
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
	clients, err := lockRuleClientsInIDOrder(ctx, q, orgID, true, rules)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.ClientID == nil {
			continue
		}
		if err := checkRuleClientCapability(r, clients[*r.ClientID]); err != nil {
			return err
		}
	}
	return nil
}

// lockRuleClientsInIDOrder locks, in ascending id order, every client
// distinctly referenced by rules' clientId, returning each locked row
// keyed by id (fix round 1, Important finding). Locking every referenced
// client up front, sorted by id rather than by rule order, matches the
// global lock order every multi-client locker in this codebase follows:
// render's LockClientsByID always locks clients FOR UPDATE in id order
// (internal/agents/settings.go's global lock-order rule). Rule order is
// caller-controlled and arbitrary; locking in that order instead risks
// deadlocking against a concurrent render holding one of these same rows
// FOR UPDATE and waiting on another (AB-BA: render locks A then waits on
// B, this locks B then waits on A).
//
// orgScoped selects which existence check follows each lock: true (a
// certificate's own rules, or an org's own default rules) scopes it to
// orgID, the same as the dnsCredentialId check above it; false (the
// cross-org global issuance_defaults settings section) checks existence
// only, mirroring dnsCredentialId's own global-vs-org split elsewhere in
// this file. orgID is ignored when orgScoped is false.
func lockRuleClientsInIDOrder(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, orgScoped bool, rules []challenge.RuleSpec) (map[uuid.UUID]sqlcgen.Client, error) {
	seen := map[uuid.UUID]bool{}
	firstMatch := map[uuid.UUID]string{}
	var ids []uuid.UUID
	for _, r := range rules {
		if r.ClientID == nil || seen[*r.ClientID] {
			continue
		}
		seen[*r.ClientID] = true
		firstMatch[*r.ClientID] = r.Match
		ids = append(ids, *r.ClientID)
	}
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	notFound := func(id uuid.UUID) error {
		if orgScoped {
			return &ValidationError{"verificationRules", "rule " + firstMatch[id] + ": client not found in this org"}
		}
		return &ValidationError{"verificationRules", "rule " + firstMatch[id] + ": no such client"}
	}
	out := make(map[uuid.UUID]sqlcgen.Client, len(ids))
	for _, id := range ids {
		if _, err := q.LockClientKeyShare(ctx, id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, notFound(id)
			}
			return nil, err
		}
		var c sqlcgen.Client
		var err error
		if orgScoped {
			c, err = q.GetClient(ctx, sqlcgen.GetClientParams{ID: id, OrgID: orgID})
		} else {
			c, err = q.GetClientByID(ctx, id)
		}
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, notFound(id)
			}
			return nil, err
		}
		out[id] = c
	}
	return out, nil
}

// checkRuleClientCapability checks that c (r's clientId) reports the
// capability r's method needs ("http-01" or "tls-alpn-01"), unless r is an
// http-01 rule with its own webroot, which needs no agent listener
// capability at all (the agent just writes the token under a path the
// operator named; see docs/agent.md#challenge-serving).
func checkRuleClientCapability(r challenge.RuleSpec, c sqlcgen.Client) error {
	if r.Method == challenge.MethodHTTP01 && r.Webroot != "" {
		return nil
	}
	needed := string(r.Method.Type())
	if !slices.Contains(c.Capabilities, needed) {
		return &ValidationError{"verificationRules", "rule " + r.Match + ": client " + c.Name + " does not serve " + needed}
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

// RenameHook runs inside UpdateCertificate's transaction when a name
// change commits, right before commit; its returned func (possibly nil)
// runs after. Used by the agents service to re-render and path-check
// grants whose Traefik target paths depend on the certificate name.
type RenameHook func(ctx context.Context, q *sqlcgen.Queries, certID uuid.UUID) (func(), error)

// UpdateCertificate replaces a definition. reissue reports that the names
// (common name or SANs) changed, which makes the certificate due now. Runs
// inside one transaction; see prepareCertTx. When in.Name differs from the
// stored name and hook is non-nil, hook runs inside the same transaction
// before commit; a hook error fails the whole update (rolled back).
func (s *Store) UpdateCertificate(ctx context.Context, orgID, id uuid.UUID, in CertInput, hook RenameHook) (c Certificate, reissue bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Certificate{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	// FOR UPDATE: a concurrent update racing this one must not compute
	// reissue from names that are already stale by the time either commits.
	curRow, err := q.GetCertificateForUpdate(ctx, sqlcgen.GetCertificateForUpdateParams{ID: id, OrgID: orgID})
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
	var after func()
	if hook != nil && cur.Name != c.Name {
		if after, err = hook(ctx, q, id); err != nil {
			return Certificate{}, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, false, err
	}
	if after != nil {
		after()
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

// ListSort is a supported certificate list sort field.
type ListSort string

// Supported certificate list sort fields.
const (
	SortName        ListSort = "name"
	SortStatus      ListSort = "status"
	SortNextRenewAt ListSort = "nextRenewAt"
	SortNotAfter    ListSort = "notAfter"
)

// ListCursor resumes a keyset page strictly after the row whose sort field
// formatted to Key and whose id is ID.
type ListCursor struct {
	Key string
	ID  uuid.UUID
}

// ListQuery is one page's filter, sort and paging request.
type ListQuery struct {
	Status string // "" = no filter
	Q      string // "" = no filter; case-insensitive substring of the name, common name, or any SAN
	Sort   ListSort
	Desc   bool
	Cursor *ListCursor // nil = first page
	Limit  int
}

// ListPage is one page of certificates plus the cursor for the next one
// (nil on the last page).
type ListPage struct {
	Certificates []Certificate
	NextCursor   *ListCursor
}

// certListRow is the shape shared by every ListCertificatesPageBy*Row type,
// used to build a Certificate without repeating the same field list eight
// times.
type certListRow struct {
	ID                uuid.UUID
	OrgID             uuid.UUID
	Name              string
	CommonName        string
	Sans              []string
	VerificationRules []byte
	Overrides         []byte
	Status            string
	CurrentVersionID  *uuid.UUID
	NextRenewAt       *time.Time
	FailureCount      int32
	LastError         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Managed           bool
	AriWindowStart    *time.Time
	AriWindowEnd      *time.Time
	AriCheckedAt      *time.Time
	AriRetryAfter     *time.Time
}

func (r certListRow) toCertificate() (Certificate, error) {
	return certFromRow(sqlcgen.Certificate{ID: r.ID, OrgID: r.OrgID, Name: r.Name, CommonName: r.CommonName, Sans: r.Sans,
		VerificationRules: r.VerificationRules, Overrides: r.Overrides, Status: r.Status, CurrentVersionID: r.CurrentVersionID,
		NextRenewAt: r.NextRenewAt, FailureCount: r.FailureCount, LastError: r.LastError, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		Managed: r.Managed, AriWindowStart: r.AriWindowStart, AriWindowEnd: r.AriWindowEnd, AriCheckedAt: r.AriCheckedAt, AriRetryAfter: r.AriRetryAfter})
}

func formatCursorTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// buildListPage trims rows (already fetched as limit+1, in sort order) to a
// page of at most limit certificates and computes the next cursor from the
// last row kept, when there were more rows than the page holds.
func buildListPage(certs []Certificate, keys []string, limit int) ListPage {
	more := len(certs) > limit
	if more {
		certs = certs[:limit]
		keys = keys[:limit]
	}
	p := ListPage{Certificates: certs}
	if more && len(certs) > 0 {
		last := len(certs) - 1
		p.NextCursor = &ListCursor{Key: keys[last], ID: certs[last].ID}
	}
	return p
}

// ListCertificatesPage returns one page of certificates across orgIDs,
// filtered by q.Status and q.Q and ordered by q.Sort (q.Desc for
// descending), every sort breaking ties on id. Unlike an offset cursor over
// an in-memory sort of the whole org, a keyset cursor stays correct while
// rows are inserted or deleted between calls: it resumes strictly after the
// specific row it names, not after a row count that shifts as the
// underlying set changes.
func (s *Store) ListCertificatesPage(ctx context.Context, orgIDs []uuid.UUID, q ListQuery) (ListPage, error) {
	hasCursor := q.Cursor != nil
	var lastID uuid.UUID
	var lastKeyText string
	var lastKeyTime time.Time
	if hasCursor {
		lastID = q.Cursor.ID
		switch q.Sort {
		case SortNextRenewAt, SortNotAfter:
			t, err := time.Parse(time.RFC3339Nano, q.Cursor.Key)
			if err != nil {
				return ListPage{}, &ValidationError{"cursor", "cursor is not from this list"}
			}
			lastKeyTime = t
		default:
			lastKeyText = q.Cursor.Key
		}
	}
	limit := int32(q.Limit + 1)
	var certs []Certificate
	var keys []string
	appendRow := func(r certListRow, key string) error {
		c, err := r.toCertificate()
		if err != nil {
			return err
		}
		certs = append(certs, c)
		keys = append(keys, key)
		return nil
	}

	switch {
	case q.Sort == SortName && !q.Desc:
		rows, err := s.q.ListCertificatesPageByNameAsc(ctx, sqlcgen.ListCertificatesPageByNameAscParams{
			OrgIds: orgIDs, StatusFilter: q.Status, QFilter: q.Q, HasCursor: hasCursor, LastKey: lastKeyText, LastID: lastID, PageLimit: limit})
		if err != nil {
			return ListPage{}, err
		}
		for _, r := range rows {
			row := certListRow{r.ID, r.OrgID, r.Name, r.CommonName, r.Sans, r.VerificationRules, r.Overrides, r.Status,
				r.CurrentVersionID, r.NextRenewAt, r.FailureCount, r.LastError, r.CreatedAt, r.UpdatedAt, r.Managed,
				r.AriWindowStart, r.AriWindowEnd, r.AriCheckedAt, r.AriRetryAfter}
			if err := appendRow(row, r.SortKey); err != nil {
				return ListPage{}, err
			}
		}
	case q.Sort == SortName && q.Desc:
		rows, err := s.q.ListCertificatesPageByNameDesc(ctx, sqlcgen.ListCertificatesPageByNameDescParams{
			OrgIds: orgIDs, StatusFilter: q.Status, QFilter: q.Q, HasCursor: hasCursor, LastKey: lastKeyText, LastID: lastID, PageLimit: limit})
		if err != nil {
			return ListPage{}, err
		}
		for _, r := range rows {
			row := certListRow{r.ID, r.OrgID, r.Name, r.CommonName, r.Sans, r.VerificationRules, r.Overrides, r.Status,
				r.CurrentVersionID, r.NextRenewAt, r.FailureCount, r.LastError, r.CreatedAt, r.UpdatedAt, r.Managed,
				r.AriWindowStart, r.AriWindowEnd, r.AriCheckedAt, r.AriRetryAfter}
			if err := appendRow(row, r.SortKey); err != nil {
				return ListPage{}, err
			}
		}
	case q.Sort == SortStatus && !q.Desc:
		rows, err := s.q.ListCertificatesPageByStatusAsc(ctx, sqlcgen.ListCertificatesPageByStatusAscParams{
			OrgIds: orgIDs, StatusFilter: q.Status, QFilter: q.Q, HasCursor: hasCursor, LastKey: lastKeyText, LastID: lastID, PageLimit: limit})
		if err != nil {
			return ListPage{}, err
		}
		for _, r := range rows {
			row := certListRow{r.ID, r.OrgID, r.Name, r.CommonName, r.Sans, r.VerificationRules, r.Overrides, r.Status,
				r.CurrentVersionID, r.NextRenewAt, r.FailureCount, r.LastError, r.CreatedAt, r.UpdatedAt, r.Managed,
				r.AriWindowStart, r.AriWindowEnd, r.AriCheckedAt, r.AriRetryAfter}
			if err := appendRow(row, r.SortKey); err != nil {
				return ListPage{}, err
			}
		}
	case q.Sort == SortStatus && q.Desc:
		rows, err := s.q.ListCertificatesPageByStatusDesc(ctx, sqlcgen.ListCertificatesPageByStatusDescParams{
			OrgIds: orgIDs, StatusFilter: q.Status, QFilter: q.Q, HasCursor: hasCursor, LastKey: lastKeyText, LastID: lastID, PageLimit: limit})
		if err != nil {
			return ListPage{}, err
		}
		for _, r := range rows {
			row := certListRow{r.ID, r.OrgID, r.Name, r.CommonName, r.Sans, r.VerificationRules, r.Overrides, r.Status,
				r.CurrentVersionID, r.NextRenewAt, r.FailureCount, r.LastError, r.CreatedAt, r.UpdatedAt, r.Managed,
				r.AriWindowStart, r.AriWindowEnd, r.AriCheckedAt, r.AriRetryAfter}
			if err := appendRow(row, r.SortKey); err != nil {
				return ListPage{}, err
			}
		}
	case q.Sort == SortNextRenewAt && !q.Desc:
		rows, err := s.q.ListCertificatesPageByNextRenewAtAsc(ctx, sqlcgen.ListCertificatesPageByNextRenewAtAscParams{
			OrgIds: orgIDs, StatusFilter: q.Status, QFilter: q.Q, HasCursor: hasCursor, LastKey: lastKeyTime, LastID: lastID, PageLimit: limit})
		if err != nil {
			return ListPage{}, err
		}
		for _, r := range rows {
			row := certListRow{r.ID, r.OrgID, r.Name, r.CommonName, r.Sans, r.VerificationRules, r.Overrides, r.Status,
				r.CurrentVersionID, r.NextRenewAt, r.FailureCount, r.LastError, r.CreatedAt, r.UpdatedAt, r.Managed,
				r.AriWindowStart, r.AriWindowEnd, r.AriCheckedAt, r.AriRetryAfter}
			var key time.Time
			if r.SortKey != nil {
				key = *r.SortKey
			}
			if err := appendRow(row, formatCursorTime(key)); err != nil {
				return ListPage{}, err
			}
		}
	case q.Sort == SortNextRenewAt && q.Desc:
		rows, err := s.q.ListCertificatesPageByNextRenewAtDesc(ctx, sqlcgen.ListCertificatesPageByNextRenewAtDescParams{
			OrgIds: orgIDs, StatusFilter: q.Status, QFilter: q.Q, HasCursor: hasCursor, LastKey: lastKeyTime, LastID: lastID, PageLimit: limit})
		if err != nil {
			return ListPage{}, err
		}
		for _, r := range rows {
			row := certListRow{r.ID, r.OrgID, r.Name, r.CommonName, r.Sans, r.VerificationRules, r.Overrides, r.Status,
				r.CurrentVersionID, r.NextRenewAt, r.FailureCount, r.LastError, r.CreatedAt, r.UpdatedAt, r.Managed,
				r.AriWindowStart, r.AriWindowEnd, r.AriCheckedAt, r.AriRetryAfter}
			var key time.Time
			if r.SortKey != nil {
				key = *r.SortKey
			}
			if err := appendRow(row, formatCursorTime(key)); err != nil {
				return ListPage{}, err
			}
		}
	case q.Sort == SortNotAfter && !q.Desc:
		rows, err := s.q.ListCertificatesPageByNotAfterAsc(ctx, sqlcgen.ListCertificatesPageByNotAfterAscParams{
			OrgIds: orgIDs, StatusFilter: q.Status, QFilter: q.Q, HasCursor: hasCursor, LastKey: lastKeyTime, LastID: lastID, PageLimit: limit})
		if err != nil {
			return ListPage{}, err
		}
		for _, r := range rows {
			row := certListRow{r.ID, r.OrgID, r.Name, r.CommonName, r.Sans, r.VerificationRules, r.Overrides, r.Status,
				r.CurrentVersionID, r.NextRenewAt, r.FailureCount, r.LastError, r.CreatedAt, r.UpdatedAt, r.Managed,
				r.AriWindowStart, r.AriWindowEnd, r.AriCheckedAt, r.AriRetryAfter}
			if err := appendRow(row, formatCursorTime(r.SortKey)); err != nil {
				return ListPage{}, err
			}
		}
	case q.Sort == SortNotAfter && q.Desc:
		rows, err := s.q.ListCertificatesPageByNotAfterDesc(ctx, sqlcgen.ListCertificatesPageByNotAfterDescParams{
			OrgIds: orgIDs, StatusFilter: q.Status, QFilter: q.Q, HasCursor: hasCursor, LastKey: lastKeyTime, LastID: lastID, PageLimit: limit})
		if err != nil {
			return ListPage{}, err
		}
		for _, r := range rows {
			row := certListRow{r.ID, r.OrgID, r.Name, r.CommonName, r.Sans, r.VerificationRules, r.Overrides, r.Status,
				r.CurrentVersionID, r.NextRenewAt, r.FailureCount, r.LastError, r.CreatedAt, r.UpdatedAt, r.Managed,
				r.AriWindowStart, r.AriWindowEnd, r.AriCheckedAt, r.AriRetryAfter}
			if err := appendRow(row, formatCursorTime(r.SortKey)); err != nil {
				return ListPage{}, err
			}
		}
	default:
		return ListPage{}, &ValidationError{"sort", "sort by one of name, notAfter, nextRenewAt, status"}
	}

	return buildListPage(certs, keys, q.Limit), nil
}

// CreateExternalCertificate stores an unmanaged (uploaded) or managed
// (imported) certificate definition inside tx (the caller's transaction,
// shared with certstore.Insert and SetCurrentVersion — see
// Service.UploadCertificate and Service.ImportCertificates). managed and
// nextRenewAt are the caller's own choice: Service.UploadCertificate
// always passes (false, nil) — the certificates_unmanaged_no_renewal CHECK
// enforces that combination — while Service.ImportCertificates passes
// (true, non-nil), since an imported certificate is managed (renewed by
// CertForge from now on) even though this call, unlike CreateCertificate,
// never itself enqueues an issuance. A duplicate (org_id, name) is a
// ConflictError (409), not the ValidationError (422) CreateCertificate's
// own duplicate-name path gives: R10's upload endpoint calls for 409, and
// ImportCertificates reuses the same signal to skip a taken name instead
// of failing the whole import.
func (s *Store) CreateExternalCertificate(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, name, commonName string, sans []string, over Defaults, managed bool, status string, nextRenewAt *time.Time) (Certificate, error) {
	overB, err := json.Marshal(over)
	if err != nil {
		return Certificate{}, err
	}
	row, err := s.q.WithTx(tx).CreateExternalCertificate(ctx, sqlcgen.CreateExternalCertificateParams{
		OrgID: orgID, Name: name, CommonName: commonName, Sans: sans, Overrides: overB,
		Managed: managed, Status: status, NextRenewAt: nextRenewAt})
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return Certificate{}, &ConflictError{Msg: fmt.Sprintf("a certificate named %q already exists", name)}
		}
		return Certificate{}, err
	}
	return certFromRow(row)
}

// LockCertificateForUpdate locks and returns a certificate FOR UPDATE
// inside tx (fix round 1: issuance.Service.UploadVersion's own
// transaction, before it decides whether the upload is refused for being
// managed or for stranding a live grant that needs a key). FOR UPDATE
// conflicts with agents.checkRefs's FOR KEY SHARE lock on the same row
// (LockCertificateForGrant), unlike the plain UPDATE SetCurrentVersion
// alone would issue (an implicit FOR NO KEY UPDATE, which does not
// conflict with FOR KEY SHARE) — see UploadVersion's own doc comment for
// why that distinction is what actually closes the race.
func (s *Store) LockCertificateForUpdate(ctx context.Context, tx pgx.Tx, orgID, id uuid.UUID) (Certificate, error) {
	row, err := s.q.WithTx(tx).GetCertificateForUpdate(ctx, sqlcgen.GetCertificateForUpdateParams{ID: id, OrgID: orgID})
	if err != nil {
		return Certificate{}, notFound(err)
	}
	return certFromRow(row)
}

// SetCurrentVersion attaches versionID as certID's current version and
// refreshes its derived fields (names, status, next_renew_at) inside tx;
// see CreateExternalCertificate.
func (s *Store) SetCurrentVersion(ctx context.Context, tx pgx.Tx, certID, versionID uuid.UUID, commonName string, sans []string, status string, nextRenewAt *time.Time) (Certificate, error) {
	row, err := s.q.WithTx(tx).SetCurrentVersion(ctx, sqlcgen.SetCurrentVersionParams{
		ID: certID, CurrentVersionID: &versionID, CommonName: commonName, Sans: sans, Status: status, NextRenewAt: nextRenewAt})
	if err != nil {
		return Certificate{}, notFound(err)
	}
	return certFromRow(row)
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
