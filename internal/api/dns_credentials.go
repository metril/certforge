package api

import (
	"context"
	"errors"
	"time"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/issuance"
)

func dnsCredOut(c issuance.DNSCredential) gen.DNSCredential {
	cfg := c.Public
	if cfg == nil {
		cfg = map[string]string{}
	}
	return gen.DNSCredential{Id: c.ID, OrgId: ptr(c.OrgID), Name: c.Name, ProviderCode: c.ProviderCode, Config: cfg,
		StoredSecrets: ptr(c.StoredSecrets), UsedBy: ptr(int(c.UsedBy)), CreatedAt: ptr(c.CreatedAt), UpdatedAt: ptr(c.UpdatedAt)}
}

// ListDNSCredentials returns the org's DNS credentials by name, without secrets.
func (s *Server) ListDNSCredentials(ctx context.Context, r gen.ListDNSCredentialsRequestObject) (gen.ListDNSCredentialsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDNSCredsRead, &r.OrgId); err != nil {
		return nil, err
	}
	creds, err := s.d.Issuance.Store.ListDNSCredentials(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out := make(gen.ListDNSCredentials200JSONResponse, 0, len(creds))
	for _, c := range creds {
		out = append(out, dnsCredOut(c))
	}
	return out, nil
}

// CreateDNSCredential validates config against the provider schema and stores it.
func (s *Server) CreateDNSCredential(ctx context.Context, r gen.CreateDNSCredentialRequestObject) (gen.CreateDNSCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDNSCredsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.Store.CreateDNSCredential(ctx, r.OrgId, r.Body.Name, r.Body.ProviderCode, r.Body.Config)
	if err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "dns_credential.create", ResourceType: "dns_credential", ResourceID: c.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": c.Name, "providerCode": c.ProviderCode}})
	return gen.CreateDNSCredential201JSONResponse(dnsCredOut(c)), nil
}

// GetDNSCredential returns one credential of the org, without secrets.
func (s *Server) GetDNSCredential(ctx context.Context, r gen.GetDNSCredentialRequestObject) (gen.GetDNSCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDNSCredsRead, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.Store.GetDNSCredential(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	return gen.GetDNSCredential200JSONResponse(dnsCredOut(c)), nil
}

// UpdateDNSCredential replaces a credential's name and config; the provider
// cannot change, and a secret field set to __unchanged__ keeps its stored value.
func (s *Server) UpdateDNSCredential(ctx context.Context, r gen.UpdateDNSCredentialRequestObject) (gen.UpdateDNSCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDNSCredsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.Store.UpdateDNSCredential(ctx, r.OrgId, r.Id, r.Body.Name, r.Body.Config)
	if err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "dns_credential.update", ResourceType: "dns_credential", ResourceID: c.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": c.Name}})
	return gen.UpdateDNSCredential200JSONResponse(dnsCredOut(c)), nil
}

// DeleteDNSCredential deletes a credential unreferenced by certificates or defaults.
func (s *Server) DeleteDNSCredential(ctx context.Context, r gen.DeleteDNSCredentialRequestObject) (gen.DeleteDNSCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDNSCredsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if err := s.d.Issuance.Store.DeleteDNSCredential(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "dns_credential.delete", ResourceType: "dns_credential", ResourceID: r.Id.String(), OrgID: &r.OrgId})
	return gen.DeleteDNSCredential204Response{}, nil
}

// TestDNSCredential presents and cleans up a live TXT record at the target
// zone, within a bounded timeout, and reports the outcome without echoing
// config values; a provider failure comes back as a 200 with ok false, not
// an API error (mapErr only recognizes not-found or an invalid zone as an
// *HTTPError, never a raw provider error).
func (s *Server) TestDNSCredential(ctx context.Context, r gen.TestDNSCredentialRequestObject) (gen.TestDNSCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDNSCredsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	start := time.Now()
	fqdn, err := s.d.Issuance.TestDNSCredential(tctx, r.OrgId, r.Id, r.Body.Zone)
	res := gen.DNSCredentialTestResult{Ok: err == nil, Fqdn: fqdn, DurationMs: int(time.Since(start).Milliseconds())}
	if err != nil {
		mapped := mapErr(err)
		var httpErr *HTTPError
		if errors.As(mapped, &httpErr) {
			return nil, mapped // not found or invalid zone
		}
		res.Error = ptr(err.Error())
	}
	return gen.TestDNSCredential200JSONResponse(res), nil
}
