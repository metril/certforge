package issuance

import (
	"context"
	"errors"
	"fmt"
	"time"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
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
}

// NewService wires production defaults.
func NewService(store *Store, certs *certstore.Store, jobs Inserter) *Service {
	return &Service{Store: store, Certs: certs, Jobs: jobs, BuildDNS: challenge.Build,
		NewRegistrar: func(ca CA) Registrar {
			return acmesigner.New(acmesigner.Config{DirectoryURL: ca.DirectoryURL, TrustBundlePEM: ca.TrustBundlePEM})
		}}
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
	m, err := s.NewRegistrar(ca).Register(ctx, email, eab)
	if err != nil {
		return Account{}, err
	}
	return s.Store.InsertAccount(ctx, orgID, caID, m)
}

// CreateCertificate stores the definition and enqueues the first issuance.
func (s *Service) CreateCertificate(ctx context.Context, orgID uuid.UUID, in CertInput) (Certificate, error) {
	c, err := s.Store.CreateCertificate(ctx, orgID, in)
	if err != nil {
		return c, err
	}
	_, err = s.EnqueueIssue(ctx, c.ID)
	return c, err
}

// UpdateCertificate stores the definition and re-issues when names changed.
func (s *Service) UpdateCertificate(ctx context.Context, orgID, id uuid.UUID, in CertInput) (Certificate, error) {
	c, reissue, err := s.Store.UpdateCertificate(ctx, orgID, id, in)
	if err != nil || !reissue {
		return c, err
	}
	_, err = s.EnqueueIssue(ctx, c.ID)
	return c, err
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
// returns the record name used.
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
		return "", err
	}
	domain := "_certforge-test." + zone
	keyAuth := "certforge-test-" + time.Now().UTC().Format("20060102T150405")
	fqdn := dns01.UnFqdn(dns01.GetChallengeInfo(domain, keyAuth).EffectiveFQDN)
	if err := p.Present(domain, "certforge-test", keyAuth); err != nil {
		return fqdn, fmt.Errorf("present %s: %w", fqdn, err)
	}
	if err := p.CleanUp(domain, "certforge-test", keyAuth); err != nil {
		return fqdn, fmt.Errorf("clean up %s: %w", fqdn, err)
	}
	return fqdn, nil
}
