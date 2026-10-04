package api

import (
	"context"
	"strings"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/issuance"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
)

// caOut maps a stored CA to its API shape. For a localca CA, config's
// internal "revoked" array (issuance.Store's own bookkeeping) is replaced
// by revokedCount, and crlUrl is filled on the CA itself and on every
// retired[] entry under the same condition (crl enabled and general.baseUrl
// set) — no key bytes ever reach config; that lives only in secret_cfg,
// which caOut never reads.
func (s *Server) caOut(ctx context.Context, c issuance.CA) gen.CA {
	var preset *gen.CAPresetCode
	if c.Preset != "" {
		p := gen.CAPresetCode(c.Preset)
		preset = &p
	}
	out := gen.CA{Id: c.ID, OrgId: c.OrgID, Name: c.Name, Preset: preset, DirectoryUrl: c.DirectoryURL,
		TrustBundlePem: c.TrustBundlePEM, EabKid: c.EABKid, HasEab: c.HasEAB, Resolvers: c.Resolvers,
		Shared: c.Shared, Type: gen.CaType(c.Type), StoredSecrets: []string{},
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
	cfg := map[string]any{}
	for k, v := range c.Config {
		cfg[k] = v
	}
	if c.Type == issuance.CATypeLocalCA {
		// chainPem is an internal reconstruction aid (every certificate
		// above the issuing certificate, kept so Issue/CRL can rebuild the
		// full chain) — not part of the LocalCaConfig contract.
		delete(cfg, "chainPem")
		if imported, _ := cfg["imported"].(bool); imported {
			out.StoredSecrets = []string{"importKeyPem"}
		}
		n := 0
		if raw, ok := cfg["revoked"]; ok {
			if arr, ok := raw.([]any); ok {
				n = len(arr)
			}
			delete(cfg, "revoked")
		}
		cfg["revokedCount"] = n
		crlOn, _ := cfg["crl"].(bool)
		base := strings.TrimSuffix(s.baseURL(ctx), "/")
		if crlOn && base != "" {
			out.CrlUrl = ptr(base + "/crl/" + c.ID.String() + ".crl")
			if retired, ok := cfg["retired"].([]any); ok {
				for _, riAny := range retired {
					if ri, ok := riAny.(map[string]any); ok {
						if serial, _ := ri["serial"].(string); serial != "" {
							ri["crlUrl"] = base + "/crl/" + c.ID.String() + "/" + serial + ".crl"
						}
					}
				}
			}
		}
	}
	out.Config = cfg
	return out
}

func caIn(b *gen.CAInput) issuance.CAInput {
	in := issuance.CAInput{Name: b.Name, EABHmac: b.EabHmac}
	if b.Preset != nil {
		in.Preset = string(*b.Preset)
	}
	if b.DirectoryUrl != nil {
		in.DirectoryURL = *b.DirectoryUrl
	}
	if b.TrustBundlePem != nil {
		in.TrustBundlePEM = *b.TrustBundlePem
	}
	if b.EabKid != nil {
		in.EABKid = *b.EabKid
	}
	if b.Resolvers != nil {
		in.Resolvers = *b.Resolvers
	}
	if b.Type != nil {
		in.Type = string(*b.Type)
	}
	if b.Config != nil {
		in.Config = *b.Config
	}
	return in
}

func accountOut(a issuance.Account) gen.AcmeAccount {
	return gen.AcmeAccount{Id: a.ID, OrgId: ptr(a.OrgID), CaId: a.CAID, Email: a.Email, Status: gen.AcmeAccountStatus(a.Status),
		RegistrationUri: a.RegistrationURI, CreatedAt: ptr(a.CreatedAt)}
}

// ListCaPresets returns the well-known ACME CAs offered on the CA screen.
func (s *Server) ListCaPresets(ctx context.Context, _ gen.ListCaPresetsRequestObject) (gen.ListCaPresetsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCAsRead, nil); err != nil {
		return nil, err
	}
	out, err := convert[[]gen.CAPreset](acmesigner.Presets())
	return gen.ListCaPresets200JSONResponse(out), err
}

// ListCas returns the org's CAs sorted by name.
func (s *Server) ListCas(ctx context.Context, r gen.ListCasRequestObject) (gen.ListCasResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCAsRead, &r.OrgId); err != nil {
		return nil, err
	}
	cas, err := s.d.Issuance.Store.ListCAs(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out := make(gen.ListCas200JSONResponse, 0, len(cas))
	for _, c := range cas {
		out = append(out, s.caOut(ctx, c))
	}
	return out, nil
}

// checkCADirectoryURL applies the notifier SSRF policy to an ACME CA's
// directoryUrl (422 naming the field): hostnames are resolved and every
// address checked, and the "notifications" allowLoopbackUrls setting is the
// opt-out for loopback hosts. An empty URL (a preset's own) and a URL equal to
// the stored one are not re-checked.
func (s *Server) checkCADirectoryURL(ctx context.Context, in issuance.CAInput, stored string) error {
	if (in.Type != "" && in.Type != issuance.CATypeACME) || in.DirectoryURL == "" || in.DirectoryURL == stored {
		return nil
	}
	allowLoopback, err := s.monitorAllowLoopback(ctx)
	if err != nil {
		return err
	}
	if err := challenge.CheckURLResolved(ctx, in.DirectoryURL, allowLoopback, s.d.HostResolver); err != nil {
		return unprocessable("directoryUrl", err.Error())
	}
	return nil
}

// CreateCa adds a CA to the org.
func (s *Server) CreateCa(ctx context.Context, r gen.CreateCaRequestObject) (gen.CreateCaResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCAsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	in := caIn(r.Body)
	if err := s.checkCADirectoryURL(ctx, in, ""); err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.Store.CreateCA(ctx, r.OrgId, in)
	if err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "ca.create", ResourceType: "ca", ResourceID: c.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": c.Name, "preset": c.Preset, "type": c.Type}})
	return gen.CreateCa201JSONResponse(s.caOut(ctx, c)), nil
}

// GetCa returns one CA of the org.
func (s *Server) GetCa(ctx context.Context, r gen.GetCaRequestObject) (gen.GetCaResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCAsRead, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.Store.GetCA(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	return gen.GetCa200JSONResponse(s.caOut(ctx, c)), nil
}

// UpdateCa replaces a CA's fields.
func (s *Server) UpdateCa(ctx context.Context, r gen.UpdateCaRequestObject) (gen.UpdateCaResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCAsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	in := caIn(r.Body)
	stored := ""
	if cur, err := s.d.Issuance.Store.GetCA(ctx, r.OrgId, r.Id); err == nil {
		stored = cur.DirectoryURL
	}
	if err := s.checkCADirectoryURL(ctx, in, stored); err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.Store.UpdateCA(ctx, r.OrgId, r.Id, in)
	if err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "ca.update", ResourceType: "ca", ResourceID: c.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": c.Name, "preset": c.Preset, "type": c.Type}})
	return gen.UpdateCa200JSONResponse(s.caOut(ctx, c)), nil
}

// DeleteCa deletes a CA unreferenced by accounts, certificates or defaults.
func (s *Server) DeleteCa(ctx context.Context, r gen.DeleteCaRequestObject) (gen.DeleteCaResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCAsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if err := s.d.Issuance.Store.DeleteCA(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "ca.delete", ResourceType: "ca", ResourceID: r.Id.String(), OrgID: &r.OrgId})
	return gen.DeleteCa204Response{}, nil
}

// RotateCa generates a fresh issuing certificate under a localca CA's root,
// retiring the current one until its own expiry.
func (s *Server) RotateCa(ctx context.Context, r gen.RotateCaRequestObject) (gen.RotateCaResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCAsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	c, newSerial, retiredSerial, err := s.d.Issuance.Store.RotateCA(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "ca.rotate", ResourceType: "ca", ResourceID: c.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"caId": c.ID.String(), "newIssuerSerial": newSerial, "retiredSerial": retiredSerial}})
	return gen.RotateCa200JSONResponse(s.caOut(ctx, c)), nil
}

// ListAcmeAccounts returns the org's ACME accounts sorted by email.
func (s *Server) ListAcmeAccounts(ctx context.Context, r gen.ListAcmeAccountsRequestObject) (gen.ListAcmeAccountsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAccountsRead, &r.OrgId); err != nil {
		return nil, err
	}
	accts, err := s.d.Issuance.Store.ListAccounts(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out := make(gen.ListAcmeAccounts200JSONResponse, 0, len(accts))
	for _, a := range accts {
		out = append(out, accountOut(a))
	}
	return out, nil
}

// CreateAcmeAccount registers an account at the CA and stores it.
func (s *Server) CreateAcmeAccount(ctx context.Context, r gen.CreateAcmeAccountRequestObject) (gen.CreateAcmeAccountResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAccountsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	a, err := s.d.Issuance.RegisterAccount(ctx, r.OrgId, r.Body.CaId, r.Body.Email)
	if err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "acme_account.create", ResourceType: "acme_account", ResourceID: a.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"email": a.Email, "caId": a.CAID.String()}})
	return gen.CreateAcmeAccount201JSONResponse(accountOut(a)), nil
}

// GetAcmeAccount returns one account of the org.
func (s *Server) GetAcmeAccount(ctx context.Context, r gen.GetAcmeAccountRequestObject) (gen.GetAcmeAccountResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAccountsRead, &r.OrgId); err != nil {
		return nil, err
	}
	a, err := s.d.Issuance.Store.GetAccount(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	return gen.GetAcmeAccount200JSONResponse(accountOut(a)), nil
}

// DeleteAcmeAccount removes a stored account; it is not deactivated at the CA.
func (s *Server) DeleteAcmeAccount(ctx context.Context, r gen.DeleteAcmeAccountRequestObject) (gen.DeleteAcmeAccountResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAccountsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if err := s.d.Issuance.Store.DeleteAccount(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "acme_account.delete", ResourceType: "acme_account", ResourceID: r.Id.String(), OrgID: &r.OrgId})
	return gen.DeleteAcmeAccount204Response{}, nil
}

// GetOrgIssuanceDefaults returns the org's own issuance defaults (unresolved).
func (s *Server) GetOrgIssuanceDefaults(ctx context.Context, r gen.GetOrgIssuanceDefaultsRequestObject) (gen.GetOrgIssuanceDefaultsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	d, err := s.d.Issuance.Store.OrgDefaults(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out, err := convert[gen.IssuanceDefaults](d)
	return gen.GetOrgIssuanceDefaults200JSONResponse(out), err
}

// PutOrgIssuanceDefaults validates and replaces the org's issuance defaults.
func (s *Server) PutOrgIssuanceDefaults(ctx context.Context, r gen.PutOrgIssuanceDefaultsRequestObject) (gen.PutOrgIssuanceDefaultsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	d, err := convert[issuance.Defaults](r.Body)
	if err != nil {
		return nil, unprocessable("defaults", err.Error())
	}
	if err := s.d.Issuance.Store.PutOrgDefaults(ctx, r.OrgId, d); err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "issuance_defaults.update", ResourceType: "issuance_defaults", ResourceID: r.OrgId.String(), OrgID: &r.OrgId})
	out, err := convert[gen.IssuanceDefaults](d)
	return gen.PutOrgIssuanceDefaults200JSONResponse(out), err
}

// GetEffectiveIssuanceDefaults resolves global and org levels, each with its source.
func (s *Server) GetEffectiveIssuanceDefaults(ctx context.Context, r gen.GetEffectiveIssuanceDefaultsRequestObject) (gen.GetEffectiveIssuanceDefaultsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	e, err := s.d.Issuance.Store.EffectiveOrg(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out, err := convert[gen.OrgEffectiveIssuanceDefaults](e)
	if err != nil {
		return nil, err
	}
	// The built-ins ride along so the client never keeps its own copy.
	if out.Builtin, err = convert[gen.IssuanceDefaults](issuance.BuiltinDefaults()); err != nil {
		return nil, err
	}
	return gen.GetEffectiveIssuanceDefaults200JSONResponse(out), nil
}
