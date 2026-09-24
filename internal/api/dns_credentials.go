package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/issuance"
)

// defaultDNSTestTimeout bounds POST .../dns-credentials/{id}/test when
// Deps.DNSTestTimeout is unset; see acquireDNSTestSlot for why the call
// also runs in a goroutine instead of relying on context cancellation.
const defaultDNSTestTimeout = 2 * time.Minute

// dnsTestSlots bounds how many DNS credential tests may run at once: each
// one makes a live call to an external provider API that can hang for the
// full timeout, and Present/CleanUp take no context so a slow or wedged
// provider ties up a goroutine for the duration regardless of the caller
// giving up. Capacity 2 keeps a burst of clicks in the UI from piling up an
// unbounded number of outbound connections; mirrors internal/authn's
// argonSlots pattern.
var dnsTestSlots = make(chan struct{}, 2)

func acquireDNSTestSlot() (release func(), ok bool) {
	select {
	case dnsTestSlots <- struct{}{}:
		return func() { <-dnsTestSlots }, true
	default:
		return func() {}, false
	}
}

// errDNSTestBusy is returned when dnsTestSlots is full; the caller must
// also call writeRetryAfter, since HTTPError carries no headers.
var errDNSTestBusy = &HTTPError{Status: http.StatusServiceUnavailable, Title: "Service busy",
	Detail: "Too many concurrent DNS credential tests; retry shortly."}

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

// dnsTestOutcome is the result of the background call TestDNSCredential
// races against its timeout.
type dnsTestOutcome struct {
	fqdn string
	err  error
}

// TestDNSCredential presents and cleans up a live TXT record at the target
// zone and reports the outcome without echoing config values (any error
// that can carry provider-echoed request detail is scrubbed by
// issuance.Service.TestDNSCredential before it reaches here); a provider
// failure comes back as a 200 with ok false, not an API error (mapErr only
// recognizes not-found or an invalid zone as an *HTTPError, never a raw
// provider error).
//
// lego's Present/CleanUp take no context, so they cannot be preempted: the
// call runs in a goroutine and is raced against a timer instead. On timeout
// the response is {ok:false, error:"timed out"} immediately, but the
// goroutine is not abandoned — it keeps running (Present, then CleanUp,
// which still needs to remove whatever Present created) against
// context.WithoutCancel(ctx), so a slow provider still gets cleaned up
// after the request that triggered it has already gotten its answer.
func (s *Server) TestDNSCredential(ctx context.Context, r gen.TestDNSCredentialRequestObject) (gen.TestDNSCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDNSCredsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	release, ok := acquireDNSTestSlot()
	if !ok {
		writeRetryAfter(ctx, "5")
		return nil, errDNSTestBusy
	}
	defer release()

	timeout := s.d.DNSTestTimeout
	if timeout <= 0 {
		timeout = defaultDNSTestTimeout
	}
	start := time.Now()
	bg := context.WithoutCancel(ctx)
	ch := make(chan dnsTestOutcome, 1)
	go func() {
		fqdn, err := s.d.Issuance.TestDNSCredential(bg, r.OrgId, r.Id, r.Body.Zone)
		ch <- dnsTestOutcome{fqdn: fqdn, err: err}
	}()

	res := gen.DNSCredentialTestResult{}
	select {
	case out := <-ch:
		res.DurationMs = int(time.Since(start).Milliseconds())
		if out.err != nil {
			mapped := mapErr(out.err)
			var httpErr *HTTPError
			if errors.As(mapped, &httpErr) {
				return nil, mapped // not found or invalid zone
			}
			res.Fqdn = out.fqdn
			res.Error = ptr(out.err.Error())
		} else {
			res.Ok = true
			res.Fqdn = out.fqdn
		}
	case <-time.After(timeout):
		res.DurationMs = int(time.Since(start).Milliseconds())
		res.Error = ptr("timed out")
	}
	s.audit(ctx, audit.Event{Action: "dnscred.test", ResourceType: "dns_credential", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"zone": r.Body.Zone, "ok": res.Ok}})
	return gen.TestDNSCredential200JSONResponse(res), nil
}
