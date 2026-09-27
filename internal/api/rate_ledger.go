package api

import (
	"context"
	"time"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/issuance"
)

func rateLimitsOut(l issuance.RateLimits) gen.RateLimits {
	return gen.RateLimits{CertsPerRegisteredDomainPerWeek: l.CertsPerRegisteredDomainPerWeek, DuplicateCertsPerWeek: l.DuplicateCertsPerWeek,
		FailedValidationsPerHour: l.FailedValidationsPerHour, NewOrdersPer3Hours: l.NewOrdersPer3Hours}
}

// GetRateLedger returns caId's current rate-limit usage. Needs certs:read;
// the CA must be visible to the org (GetCA's own org scoping) or this 404s.
// certificate, when given, must also be in this CA's org, and narrows
// duplicateCertsPerWeek to its names. Item scopes (registered domains) are
// limited to domains the calling org has certificates in against this CA;
// every count stays CA-wide (pre-flight ruling C5).
func (s *Server) GetRateLedger(ctx context.Context, r gen.GetRateLedgerRequestObject) (gen.GetRateLedgerResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	ca, err := s.d.Issuance.Store.GetCA(ctx, r.OrgId, r.Params.Ca)
	if err != nil {
		return nil, mapErr(err)
	}
	var cert *issuance.Certificate
	if r.Params.Certificate != nil {
		c, err := s.d.Issuance.Store.GetCertificate(ctx, r.OrgId, *r.Params.Certificate)
		if err != nil {
			return nil, mapErr(err)
		}
		cert = &c
	}
	cfg, err := issuance.LoadIssuanceSettings(ctx, s.d.Settings)
	if err != nil {
		return nil, err
	}
	items, err := s.d.Issuance.Store.RateLedgerReport(ctx, r.OrgId, ca.ID, cfg.RateLimits, cert, time.Now())
	if err != nil {
		return nil, err
	}
	out := gen.RateLedger{CaId: ca.ID, Enforced: !ca.Staging(), Limits: rateLimitsOut(cfg.RateLimits), Items: make([]gen.RateLedgerItem, len(items))}
	for i, it := range items {
		out.Items[i] = gen.RateLedgerItem{Limit: gen.RateLimitName(it.Limit), Scope: it.Scope, Count: it.Count, Max: it.Max,
			WindowSeconds: it.WindowSeconds, ResetsAt: it.ResetsAt}
	}
	return gen.GetRateLedger200JSONResponse(out), nil
}
