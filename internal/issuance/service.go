package issuance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/importer"
	"github.com/metril/certforge/internal/signer"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
)

// Registrar registers ACME accounts; *acmesigner.Signer implements it.
type Registrar interface {
	Register(ctx context.Context, email string, eab *acmesigner.EAB) (signer.AccountMaterial, error)
}

// Service is the API-facing facade over Store, certstore and the job queue.
type Service struct {
	Store        *Store
	Certs        *certstore.Store
	Jobs         Inserter
	NewRegistrar func(CA) Registrar
	BuildDNS     func(code string, cfg map[string]string) (legochallenge.Provider, error)

	// Auditor records certificate.create/certificate.update right after the
	// write transaction commits and before EnqueueIssue runs, so the audit
	// trail reflects a write that has already durably happened even when
	// enqueuing the follow-up job then fails. nil disables it (tests that
	// don't exercise auditing).
	Auditor *audit.Auditor
	// Log receives a warning when an audit write or EnqueueIssue fails
	// after a successful certificate write; nil defaults to slog.Default().
	Log *slog.Logger

	// RenameHook runs inside Store.UpdateCertificate's transaction when a
	// certificate's name changes; nil skips it. Wired to
	// agents.Service.ResyncCertificateRename in production, so a rename
	// that would make two of a client's grants write the same Traefik path
	// (certs/<SafeName>) fails the rename itself, and grants otherwise
	// re-render with the new name in the same transaction as the rename.
	RenameHook RenameHook

	// Listeners hears about every version UploadCertificate/UploadVersion
	// stores, exactly like IssueWorker.Listeners does for an ordinary
	// issuance; wired to the same agents.Service in production (see
	// cmd/certforge/serve.go), so a grant already on a certificate re-
	// renders once its uploaded version commits.
	Listeners []VersionListener

	// KeylessGrantHook backs UploadVersion's keyless-grant rule (R10, fix
	// round 1): nil disables the check. Wired to agents.LiveGrantsNeedKeyTx
	// in production (cmd/certforge/serve.go); see KeylessGrantHook's own
	// doc comment (upload.go) for why this is a plain function value, not
	// a method on some agents type this package would have to import.
	KeylessGrantHook KeylessGrantHook

	// Importers overrides ImportCertificates' layout detection (tests
	// only); nil uses defaultImporters (importer.AcmeSh, importer.Certbot).
	Importers []importer.Importer
}

// notifyVersion calls every listener; a panicking listener is logged and
// never stops the others or the caller (matches IssueWorker.notifyVersion).
func (s *Service) notifyVersion(ctx context.Context, certID, versionID uuid.UUID) {
	for _, l := range s.Listeners {
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.logger().Error("version listener panicked", "cert", certID, "version", versionID, "panic", r)
				}
			}()
			l.OnVersion(ctx, certID, versionID)
		}()
	}
}

// NewService wires production defaults.
func NewService(store *Store, certs *certstore.Store, jobs Inserter) *Service {
	return &Service{Store: store, Certs: certs, Jobs: jobs, BuildDNS: challenge.Build,
		NewRegistrar: func(ca CA) Registrar {
			return acmesigner.New(acmesigner.Config{DirectoryURL: ca.DirectoryURL, TrustBundlePEM: ca.TrustBundlePEM})
		}}
}

func (s *Service) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// auditCertificateWrite records action ("create" or "update") for c. A
// failed audit write is logged, not returned: by the time this runs the
// write it documents has already committed, so there is nothing left to
// roll back.
func (s *Service) auditCertificateWrite(ctx context.Context, c Certificate, action string, details map[string]any) {
	if s.Auditor == nil {
		return
	}
	org := c.OrgID
	event := audit.Event{Action: "certificate." + action, ResourceType: "certificate", ResourceID: c.ID.String(), OrgID: &org, Details: details}
	if err := s.Auditor.Record(ctx, event); err != nil {
		s.logger().Error("audit record failed", "action", event.Action, "certificate", c.ID, "err", err)
	}
}

// enqueueBestEffort calls EnqueueIssue and logs, rather than returns, a
// failure: the certificate write it follows has already committed, so
// failing the request here would report a 500 for a change that in fact
// succeeded, and the periodic scheduler will pick the certificate up within
// SchedulePeriod regardless.
func (s *Service) enqueueBestEffort(ctx context.Context, certID uuid.UUID, reason string) {
	if _, err := s.EnqueueIssue(ctx, certID); err != nil {
		s.logger().Warn("enqueue issuance failed; the periodic scheduler will pick it up", "certificate", certID, "reason", reason, "err", err)
	}
}

// RegisterAccount registers email at the CA (with the CA's EAB) and stores
// the account. CA errors come back as *signer.Error.
func (s *Service) RegisterAccount(ctx context.Context, orgID, caID uuid.UUID, email string) (Account, error) {
	if email == "" {
		return Account{}, &ValidationError{"email", "required"}
	}
	ca, err := s.Store.GetCA(ctx, orgID, caID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Account{}, &ValidationError{"caId", "no such CA in this org"}
		}
		return Account{}, err
	}
	eab, err := s.Store.CAEAB(ctx, orgID, caID)
	if err != nil {
		return Account{}, err
	}
	// Checked before registering: the unique (ca_id, email) constraint would
	// only fire after the CA already holds a new, never-stored account.
	exists, err := s.Store.q.AccountExistsByEmail(ctx, sqlcgen.AccountExistsByEmailParams{CaID: caID, Email: email})
	if err != nil {
		return Account{}, err
	}
	if exists {
		return Account{}, &ConflictError{Msg: "an account with this email already exists for this CA"}
	}
	m, err := s.NewRegistrar(ca).Register(ctx, email, eab)
	if err != nil {
		return Account{}, err
	}
	a, err := s.Store.InsertAccount(ctx, orgID, caID, m)
	if err != nil {
		// The CA holds an account CertForge could not store; the URI lets the
		// operator find and deactivate it there.
		s.logger().Error("account registered at the CA but not stored", "caId", caID, "email", email,
			"registrationUri", m.RegistrationURI, "error", err)
		return Account{}, err
	}
	return a, nil
}

// validateWildcardMethods rejects a certificate whose own rules (its Rules
// plus any cert-level VerificationRules override, the same two sources
// buildRouter combines at issuance time) route one of its wildcard SANs to
// http-01 or tls-alpn-01: no ACME CA ever offers those challenges for a
// wildcard authorization. Per the controller ruling (challenge.Router.
// ruleFor applies the same rule once a real Router is built), a wildcard
// name does not stop at the first matching rule the way a normal name does:
// an http-01/tls-alpn-01 match is skipped and checking continues with the
// next rule in order, since that rule can never prove a wildcard anyway. A
// wildcard SAN this ends up matching no eligible rule for is only flagged
// when at least one rule DID match it (and was skipped) — a rule someone
// wrote targeting this exact name with an impossible method is a real
// mistake worth catching now, even though an org/global catch-all could in
// principle still save it. A wildcard matched by nothing at all is not
// flagged: it may be covered by such a catch-all, only known at issuance
// time. in.CommonName/SANs are normalized the same way Store.prepareCertTx
// normalizes them; a normalization error surfaces from there instead, so one
// here is silently ignored.
func validateWildcardMethods(in CertInput) error {
	names, err := NormalizeNames(in.CommonName, in.SANs)
	if err != nil {
		return nil
	}
	rules := in.Rules
	if in.Overrides.VerificationRules != nil {
		rules = append(append([]challenge.RuleSpec{}, rules...), *in.Overrides.VerificationRules...)
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "*.") {
			continue
		}
		var skipped challenge.Type
		for _, r := range rules {
			m, err := challenge.ParseMatch(r.Match)
			if err != nil || !m.Matches(n) {
				continue
			}
			if t := r.Method.Type(); t == challenge.HTTP01 || t == challenge.TLSALPN01 {
				skipped = t
				continue // ruling: wildcard skips this rule, tries the next
			}
			skipped = "" // resolved to an eligible (dns-01/manual-dns) rule
			break
		}
		if skipped != "" {
			return &ValidationError{"verificationRules", fmt.Sprintf("wildcard name %s cannot use %s", n, skipped)}
		}
	}
	return nil
}

// CreateCertificate stores the definition, audits the write, and enqueues
// the first issuance. A failed enqueue does not fail the call; see
// enqueueBestEffort.
func (s *Service) CreateCertificate(ctx context.Context, orgID uuid.UUID, in CertInput) (Certificate, error) {
	if err := validateWildcardMethods(in); err != nil {
		return Certificate{}, err
	}
	c, err := s.Store.CreateCertificate(ctx, orgID, in)
	if err != nil {
		return c, err
	}
	s.auditCertificateWrite(ctx, c, "create", map[string]any{"name": c.Name, "commonName": c.CommonName, "sans": c.SANs})
	s.enqueueBestEffort(ctx, c.ID, "create")
	return c, nil
}

// UpdateCertificate stores the definition, audits the write, and re-issues
// when names changed. A failed enqueue does not fail the call; see
// enqueueBestEffort.
func (s *Service) UpdateCertificate(ctx context.Context, orgID, id uuid.UUID, in CertInput) (Certificate, error) {
	if err := validateWildcardMethods(in); err != nil {
		return Certificate{}, err
	}
	c, reissue, err := s.Store.UpdateCertificate(ctx, orgID, id, in, s.RenameHook)
	if err != nil {
		return c, err
	}
	s.auditCertificateWrite(ctx, c, "update", map[string]any{"name": c.Name})
	if reissue {
		s.enqueueBestEffort(ctx, c.ID, "update")
	}
	return c, nil
}

// EnqueueIssue inserts an issue job; false means one is already queued or running.
func (s *Service) EnqueueIssue(ctx context.Context, certID uuid.UUID) (bool, error) {
	res, err := s.Jobs.Insert(ctx, IssueArgs{CertID: certID}, nil)
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

// TestDNSCredential presents and cleans up a TXT record for
// _certforge-test.<zone> (lego providers always add the _acme-challenge.
// prefix, so the record is _acme-challenge._certforge-test.<zone>) and
// returns the record name used. CleanUp always runs, even when Present
// failed partway through (some providers create the record before
// returning an error), so a failed test never leaves the record behind;
// Present's error takes priority when both fail. Every error that can
// carry provider-echoed request detail (BuildDNS, Present, CleanUp) is
// scrubbed against cfg (challenge.Scrub) before it reaches the caller, so a
// live provider failure never leaks a write-only secret back out.
func (s *Service) TestDNSCredential(ctx context.Context, orgID, id uuid.UUID, zone string) (string, error) {
	zone = dns01.UnFqdn(zone)
	if zone == "" {
		return "", &ValidationError{"zone", "required"}
	}
	cred, cfg, err := s.Store.DNSCredentialConfig(ctx, orgID, id)
	if err != nil {
		return "", err
	}
	p, err := s.BuildDNS(cred.ProviderCode, cfg)
	if err != nil {
		return "", challenge.Scrub(err, cred.ProviderCode, cfg)
	}
	domain := "_certforge-test." + zone
	keyAuth := "certforge-test-" + time.Now().UTC().Format("20060102T150405")
	fqdn := dns01.UnFqdn(dns01.GetChallengeInfo(domain, keyAuth).EffectiveFQDN)
	presentErr := challenge.Scrub(p.Present(domain, "certforge-test", keyAuth), cred.ProviderCode, cfg)
	cleanErr := challenge.Scrub(p.CleanUp(domain, "certforge-test", keyAuth), cred.ProviderCode, cfg)
	if presentErr != nil {
		return fqdn, fmt.Errorf("present %s: %w", fqdn, presentErr)
	}
	if cleanErr != nil {
		return fqdn, fmt.Errorf("clean up %s: %w", fqdn, cleanErr)
	}
	return fqdn, nil
}
