package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/render"
)

// ariWindowOut renders the ARI window cached on c (Task 12), nil until a
// poll has stored one (all three fields, ari.go's SetARIWindow, are always
// written together).
func ariWindowOut(c issuance.Certificate) *gen.AriWindow {
	if c.AriWindowStart == nil || c.AriWindowEnd == nil || c.AriCheckedAt == nil {
		return nil
	}
	return &gen.AriWindow{Start: *c.AriWindowStart, End: *c.AriWindowEnd, CheckedAt: *c.AriCheckedAt}
}

func versionOut(v certstore.Version) gen.CertificateVersion {
	return gen.CertificateVersion{Id: v.ID, Serial: v.Serial, NotBefore: v.NotBefore, NotAfter: v.NotAfter,
		Sha256Fingerprint: v.SHA256, KeyType: ptr(gen.KeyType(v.KeyType)), Source: gen.CertificateVersionSource(v.Source),
		HasKey: v.HasKey, RevokedAt: v.RevokedAt, CreatedAt: ptr(v.CreatedAt)}
}

// certRender builds the API shape from a domain certificate, its
// already-resolved effective config, and its current version (nil when
// none). Splitting resolution from rendering lets ListCertificates resolve
// the effective config and load current versions once for the whole page
// instead of once per certificate; certOut below is the single-item
// convenience wrapper used by the other handlers, where that batching does
// not matter.
func (s *Server) certRender(c issuance.Certificate, eff issuance.Effective, v *certstore.Version) (gen.Certificate, error) {
	rules, err := convert[[]gen.VerificationRule](c.Rules)
	if err != nil {
		return gen.Certificate{}, err
	}
	over, err := convert[gen.IssuanceDefaults](c.Overrides)
	if err != nil {
		return gen.Certificate{}, err
	}
	effOut, err := convert[gen.EffectiveIssuanceDefaults](eff)
	if err != nil {
		return gen.Certificate{}, err
	}
	out := gen.Certificate{Id: c.ID, OrgId: ptr(c.OrgID), Name: c.Name, CommonName: c.CommonName, Sans: c.SANs,
		VerificationRules: rules, Overrides: over, Status: gen.CertificateStatus(c.Status), Managed: c.Managed, NextRenewAt: c.NextRenewAt,
		FailureCount: c.FailureCount, Effective: effOut, AriWindow: ariWindowOut(c), CreatedAt: ptr(c.CreatedAt), UpdatedAt: ptr(c.UpdatedAt)}
	if c.LastError != "" {
		out.LastError = ptr(c.LastError)
	}
	if v != nil {
		out.CurrentVersion = ptr(versionOut(*v))
	}
	return out, nil
}

// certOut renders one certificate, resolving its effective config and
// current version with their own queries. EffectiveFor can itself fail with
// a *issuance.ValidationError (Task 9: a certificate-level accountId
// override against a private effective CA) — mapErr turns that into the
// same 422 a create/update validation failure would give, rather than an
// unmapped 500.
func (s *Server) certOut(ctx context.Context, c issuance.Certificate) (gen.Certificate, error) {
	eff, err := s.d.Issuance.Store.EffectiveFor(ctx, c)
	if err != nil {
		return gen.Certificate{}, mapErr(err)
	}
	var v *certstore.Version
	if c.CurrentVersionID != nil {
		vv, err := s.d.Certs.Get(ctx, c.ID, *c.CurrentVersionID)
		if err != nil {
			return gen.Certificate{}, mapErr(err)
		}
		v = &vv
	}
	o, err := s.certRender(c, eff, v)
	return o, mapErr(err)
}

func certIn(b *gen.CertificateInput) (issuance.CertInput, error) {
	in := issuance.CertInput{Name: b.Name, CommonName: b.CommonName}
	if b.Sans != nil {
		in.SANs = *b.Sans
	}
	if b.VerificationRules != nil {
		rules, err := convert[[]challenge.RuleSpec](*b.VerificationRules)
		if err != nil {
			return in, unprocessable("verificationRules", err.Error())
		}
		in.Rules = rules
	}
	if b.Overrides != nil {
		d, err := convert[issuance.Defaults](*b.Overrides)
		if err != nil {
			return in, unprocessable("overrides", err.Error())
		}
		in.Overrides = d
	}
	return in, nil
}

// ListCertificates returns one page of an org's certificates.
func (s *Server) ListCertificates(ctx context.Context, r gen.ListCertificatesRequestObject) (gen.ListCertificatesResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	var status *string
	if r.Params.Status != nil {
		status = ptr(string(*r.Params.Status))
	}
	out, err := s.listCerts(ctx, []uuid.UUID{r.OrgId}, status, r.Params.Q, r.Params.Sort, r.Params.Limit, r.Params.Cursor)
	if err != nil {
		return nil, err
	}
	return gen.ListCertificates200JSONResponse(out), nil
}

// ListAllCertificates is ListCertificates over every org the caller can read.
func (s *Server) ListAllCertificates(ctx context.Context, r gen.ListAllCertificatesRequestObject) (gen.ListAllCertificatesResponseObject, error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	orgs := authz.OrgsWith(p, authz.ActionCertsRead)
	if len(orgs) == 0 {
		return nil, &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "missing permission certs:read"}
	}
	var status *string
	if r.Params.Status != nil {
		status = ptr(string(*r.Params.Status))
	}
	out, err := s.listCerts(ctx, orgs, status, r.Params.Q, r.Params.Sort, r.Params.Limit, r.Params.Cursor)
	if err != nil {
		return nil, err
	}
	return gen.ListAllCertificates200JSONResponse(out), nil
}

// listCerts returns one keyset page of orgIDs' certificates, filtered by
// status and q and ordered by sort. Pagination resumes strictly after a
// specific (sort key, id) pair rather than an in-memory row count, so it
// stays correct while certificates are created or deleted between pages.
// The effective config (global and per-org defaults) and every
// certificate's current version on this page are each loaded once for the
// whole page, not once per certificate; org defaults are cached per org so
// a cross-org page does not re-fetch them per row. An inherited ACME
// account is dropped for a private effective CA exactly as GET does
// (issuance.DropAccountForPrivateCA), with the CA itself cached per id.
func (s *Server) listCerts(ctx context.Context, orgIDs []uuid.UUID, status, q, sort *string, limit *int, cursor *string) (gen.CertificateList, error) {
	p, err := parseCertList(status, q, sort, limit, cursor)
	if err != nil {
		return gen.CertificateList{}, err
	}
	lq := issuance.ListQuery{Status: p.status, Q: p.q, Sort: issuance.ListSort(p.sort), Desc: p.desc, Limit: p.limit}
	if p.cursor != nil {
		lq.Cursor = &issuance.ListCursor{Key: p.cursor.LastKey, ID: p.cursor.LastID}
	}
	pg, err := s.d.Issuance.Store.ListCertificatesPage(ctx, orgIDs, lq)
	if err != nil {
		return gen.CertificateList{}, mapErr(err)
	}
	global, err := s.d.Issuance.Store.GlobalDefaults(ctx)
	if err != nil {
		return gen.CertificateList{}, err
	}
	orgDefaults := map[uuid.UUID]issuance.Defaults{}
	var versionIDs []uuid.UUID
	for _, c := range pg.Certificates {
		if _, ok := orgDefaults[c.OrgID]; !ok {
			d, err := s.d.Issuance.Store.OrgDefaults(ctx, c.OrgID)
			if err != nil {
				return gen.CertificateList{}, err
			}
			orgDefaults[c.OrgID] = d
		}
		if c.CurrentVersionID != nil {
			versionIDs = append(versionIDs, *c.CurrentVersionID)
		}
	}
	versions, err := s.d.Certs.Versions(ctx, versionIDs)
	if err != nil {
		return gen.CertificateList{}, err
	}
	// cas caches one CA row per distinct id resolved on this page (like
	// orgDefaults above), so DropAccountForPrivateCA's reconciliation —
	// the same rule EffectiveFor applies on GET — costs at most one extra
	// query per distinct CA, not one per certificate.
	cas := map[uuid.UUID]issuance.CA{}
	items := make([]gen.Certificate, 0, len(pg.Certificates))
	for _, c := range pg.Certificates {
		eff := issuance.Resolve(global, orgDefaults[c.OrgID], c.Overrides)
		if eff.CAID.Value != nil && eff.AccountID.Value != nil {
			ca, ok := cas[*eff.CAID.Value]
			if !ok {
				var caErr error
				ca, caErr = s.d.Issuance.Store.GetCA(ctx, c.OrgID, *eff.CAID.Value)
				if caErr != nil {
					return gen.CertificateList{}, caErr
				}
				cas[*eff.CAID.Value] = ca
			}
			eff = issuance.DropAccountForPrivateCA(eff, ca)
		}
		var v *certstore.Version
		if c.CurrentVersionID != nil {
			if vv, ok := versions[*c.CurrentVersionID]; ok {
				v = &vv
			}
		}
		o, err := s.certRender(c, eff, v)
		if err != nil {
			return gen.CertificateList{}, err
		}
		items = append(items, o)
	}
	var next *string
	if pg.NextCursor != nil {
		n := encodeCertCursor(certCursor{Sort: p.sort, Desc: p.desc, Q: p.q, Status: p.status,
			LastKey: pg.NextCursor.Key, LastID: pg.NextCursor.ID})
		next = &n
	}
	if err := s.addGrantCounts(ctx, items); err != nil {
		return gen.CertificateList{}, err
	}
	return gen.CertificateList{Items: items, NextCursor: next}, nil
}

// CreateCertificate stores a definition and queues the first issuance. The
// audit event and the (best-effort) enqueue happen inside
// Issuance.CreateCertificate, right after the write commits, not here: a
// failure enqueuing must not turn an already-committed write into a 500.
func (s *Server) CreateCertificate(ctx context.Context, r gen.CreateCertificateRequestObject) (gen.CreateCertificateResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	in, err := certIn(r.Body)
	if err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.CreateCertificate(ctx, r.OrgId, in)
	if err != nil {
		return nil, mapErr(err)
	}
	o, err := s.certOut(ctx, c)
	return gen.CreateCertificate201JSONResponse(o), err
}

// GetCertificate returns one certificate of the org.
func (s *Server) GetCertificate(ctx context.Context, r gen.GetCertificateRequestObject) (gen.GetCertificateResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.Store.GetCertificate(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	o, err := s.certOut(ctx, c)
	return gen.GetCertificate200JSONResponse(o), err
}

// UpdateCertificate replaces a definition; changing names queues a new
// issuance, other changes apply at the next renewal. 409 "managed
// externally" for an unmanaged certificate (managed false): CertForge
// never edits a certificate it does not renew itself, only uploads a new
// version onto it (uploadCertificateVersion). The audit event and the
// (best-effort) enqueue happen inside Issuance.UpdateCertificate, right
// after the write commits; see CreateCertificate.
func (s *Server) UpdateCertificate(ctx context.Context, r gen.UpdateCertificateRequestObject) (gen.UpdateCertificateResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	cur, err := s.d.Issuance.Store.GetCertificate(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	if !cur.Managed {
		return nil, conflict("managed externally")
	}
	in, err := certIn(r.Body)
	if err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.UpdateCertificate(ctx, r.OrgId, r.Id, in)
	if err != nil {
		return nil, mapErr(err)
	}
	o, err := s.certOut(ctx, c)
	return gen.UpdateCertificate200JSONResponse(o), err
}

// DeleteCertificate deletes the definition with all versions and attempts
// (the migration cascades certificate_versions, issuance_attempts, and
// manual_pending on the certificate row); it does not revoke. A job already
// queued for this certificate finds it gone and is a no-op
// (IssueWorker.Issue returns nil on ErrNotFound); no explicit cancel is
// needed.
// DeleteCertificate locks the certificate row FOR UPDATE (GetCertificateForUpdate)
// before counting its grants and deleting it, all in one transaction: a
// bare read-then-delete over the pool could otherwise race a concurrent
// CreateGrant, which locks the same row FOR KEY SHARE (an incompatible
// mode) before inserting — see agents.Service.CreateGrant. The grant count
// includes removal-pending grants (any row still present), not just live
// ones, since cert_id is ON DELETE CASCADE and a removal-pending grant
// still needs its agent to confirm the files are gone. It also 409s when a
// layout still lists this certificate as an extra certificate
// (LayoutsListingExtraCert): output_specs.extra_cert_ids has no FK, so
// deleting the certificate out from under it would leave a dangling id.
func (s *Server) DeleteCertificate(ctx context.Context, r gen.DeleteCertificateRequestObject) (gen.DeleteCertificateResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	if _, err := q.GetCertificateForUpdate(ctx, sqlcgen.GetCertificateForUpdateParams{ID: r.Id, OrgID: r.OrgId}); errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("certificate %s", r.Id)
	} else if err != nil {
		return nil, err
	}
	rows, err := q.CountAllGrantsByCert(ctx, []uuid.UUID{r.Id})
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 && rows[0].Grants > 0 {
		return nil, conflict("This certificate is granted to %d client(s); remove and confirm those grants first.", rows[0].Grants)
	}
	layouts, err := q.LayoutsListingExtraCert(ctx, sqlcgen.LayoutsListingExtraCertParams{OrgID: r.OrgId, CertID: r.Id})
	if err != nil {
		return nil, err
	}
	if len(layouts) > 0 {
		return nil, extraCertConflict(layouts)
	}
	n, err := q.DeleteCertificate(ctx, sqlcgen.DeleteCertificateParams{ID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, notFound("certificate %s", r.Id)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "certificate.delete", ResourceType: "certificate", ResourceID: r.Id.String(), OrgID: &r.OrgId})
	return gen.DeleteCertificate204Response{}, nil
}

// RenewCertificate queues an issuance now; enqueued is false when one is
// already queued or running (the unique issue job then just keeps going).
// 409 "managed externally" for an unmanaged certificate (managed false):
// CertForge never renews a certificate it did not issue itself.
func (s *Server) RenewCertificate(ctx context.Context, r gen.RenewCertificateRequestObject) (gen.RenewCertificateResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsIssue, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.d.Issuance.Store.GetCertificate(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	if !c.Managed {
		return nil, conflict("managed externally")
	}
	ok, err := s.d.Issuance.EnqueueIssue(ctx, r.Id)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "certificate.renew", ResourceType: "certificate", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"enqueued": ok}})
	return gen.RenewCertificate202JSONResponse{Enqueued: ok}, nil
}

// ListCertificateVersions returns a certificate's issued versions, newest first.
func (s *Server) ListCertificateVersions(ctx context.Context, r gen.ListCertificateVersionsRequestObject) (gen.ListCertificateVersionsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	if _, err := s.d.Issuance.Store.GetCertificate(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapErr(err)
	}
	vs, err := s.d.Certs.List(ctx, r.Id)
	if err != nil {
		return nil, err
	}
	out := make(gen.ListCertificateVersions200JSONResponse, 0, len(vs))
	for _, v := range vs {
		out = append(out, versionOut(v))
	}
	return out, nil
}

// revocationReasonCodes maps RevocationReason to its RFC 5280 §5.3.1
// CRLReason code.
var revocationReasonCodes = map[gen.RevocationReason]int{
	gen.Unspecified:          0,
	gen.KeyCompromise:        1,
	gen.CaCompromise:         2,
	gen.AffiliationChanged:   3,
	gen.Superseded:           4,
	gen.CessationOfOperation: 5,
}

// RevokeCertificateVersion revokes one issued private-CA certificate
// version, feeding its issuer's CRL from the next build.
func (s *Server) RevokeCertificateVersion(ctx context.Context, r gen.RevokeCertificateVersionRequestObject) (gen.RevokeCertificateVersionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsIssue, &r.OrgId); err != nil {
		return nil, err
	}
	reason := gen.Unspecified
	if r.Body != nil && r.Body.Reason != nil {
		reason = *r.Body.Reason
	}
	v, err := s.d.Issuance.Store.RevokeVersion(ctx, r.OrgId, r.Id, r.Vid, revocationReasonCodes[reason], s.baseURL)
	if err != nil {
		return nil, mapErr(err)
	}
	s.audit(ctx, audit.Event{Action: "certificate.revoked", ResourceType: "certificate_version", ResourceID: v.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"certificateId": r.Id.String(), "versionId": v.ID.String(), "serial": v.Serial, "reason": string(reason)}})
	return gen.RevokeCertificateVersion200JSONResponse(versionOut(v)), nil
}

// ListIssuanceAttempts returns a certificate's 50 newest attempts with their
// step timeline and log.
func (s *Server) ListIssuanceAttempts(ctx context.Context, r gen.ListIssuanceAttemptsRequestObject) (gen.ListIssuanceAttemptsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	as, err := s.d.Issuance.Store.ListAttempts(ctx, r.OrgId, r.Id, 50)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make(gen.ListIssuanceAttempts200JSONResponse, 0, len(as))
	for _, a := range as {
		steps, err := convert[[]gen.AttemptStep](a.Steps)
		if err != nil {
			return nil, err
		}
		it := gen.IssuanceAttempt{Id: a.ID, StartedAt: a.StartedAt, FinishedAt: a.FinishedAt,
			Outcome: gen.IssuanceAttemptOutcome(a.Outcome), RetryAfter: a.RetryAfter, Steps: steps, Log: a.Log}
		if a.ACMEErrorType != "" {
			it.AcmeErrorType = ptr(a.ACMEErrorType)
		}
		out = append(out, it)
	}
	return out, nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// DownloadCertificateVersion renders pem or der parts of one version
// through render.For(format). Parts containing the key (key, combined) need
// keys:export and are audited before any byte is returned: the audit call
// here bypasses the fire-and-forget s.audit helper and returns its own
// error instead, since a failed audit write must block the download rather
// than merely being logged. A version with no stored key (imported without
// one) reports 404, same as any other missing part of the request, not
// 500. der only holds cert, chain and key, one part per file;
// render.ErrNotDER (fullchain, combined) is 422.
func (s *Server) DownloadCertificateVersion(ctx context.Context, r gen.DownloadCertificateVersionRequestObject) (gen.DownloadCertificateVersionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	format := "pem"
	if r.Params.Format != nil {
		format = string(*r.Params.Format)
	}
	// Download only ever produces pem or der: p12/jks always need a
	// password, which this endpoint has no field for, so they can never
	// succeed here. Rejecting them by name before render.For (rather than
	// letting them reach the renderer and fail there) avoids decrypting the
	// stored key for a request that can never complete, and keeps the error
	// about format, not a password/parts message that would otherwise
	// surface from deep inside the p12/jks renderer.
	if format != "pem" && format != "der" {
		return nil, unprocessable("format", fmt.Sprintf("unknown format %q; valid: pem, der", format))
	}
	renderer, _ := render.For(format)
	var parts []string
	for _, p := range strings.Split(r.Params.Parts, ",") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	needKey := slices.Contains(parts, "key") || slices.Contains(parts, "combined")
	if needKey {
		if _, err := authorize(ctx, authz.ActionKeysExport, &r.OrgId); err != nil {
			return nil, err
		}
	}
	c, err := s.d.Issuance.Store.GetCertificate(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	m, err := s.d.Certs.Material(ctx, c.ID, r.Vid, needKey)
	if err != nil {
		return nil, mapErr(err)
	}
	files, err := renderer.Render(m, render.OutputOpts{Parts: parts})
	if err != nil {
		if errors.Is(err, render.ErrNoKey) {
			return nil, &HTTPError{Status: http.StatusNotFound, Title: "Not found", Detail: "this version has no stored private key"}
		}
		if errors.Is(err, render.ErrNotDER) {
			return nil, unprocessable("parts", err.Error())
		}
		return nil, unprocessable("parts", err.Error()+"; valid: "+strings.Join(render.Parts, ", "))
	}
	if needKey {
		org := r.OrgId
		if err := s.d.Auditor.Record(ctx, audit.Event{Action: "certificate.key_exported", ResourceType: "certificate_version",
			ResourceID: r.Vid.String(), OrgID: &org, Details: map[string]any{"certificateId": c.ID.String(), "parts": parts, "format": format}}); err != nil {
			return nil, fmt.Errorf("audit key export: %w", err)
		}
	}
	base := unsafeName.ReplaceAllString(c.Name, "_")
	if len(files) == 1 {
		f := files[0]
		headers := gen.DownloadCertificateVersion200ResponseHeaders{ContentDisposition: fmt.Sprintf(`attachment; filename="%s-%s"`, base, f.Name)}
		if f.ContentType == "application/octet-stream" {
			return gen.DownloadCertificateVersion200ApplicationoctetStreamResponse{Body: bytes.NewReader(f.Data), ContentLength: int64(len(f.Data)),
				Headers: headers}, nil
		}
		return gen.DownloadCertificateVersion200ApplicationxPemFileResponse{Body: bytes.NewReader(f.Data), ContentLength: int64(len(f.Data)),
			Headers: headers}, nil
	}
	z, err := render.Zip(files)
	if err != nil {
		return nil, err
	}
	return gen.DownloadCertificateVersion200ApplicationzipResponse{Body: bytes.NewReader(z), ContentLength: int64(len(z)),
		Headers: gen.DownloadCertificateVersion200ResponseHeaders{ContentDisposition: fmt.Sprintf(`attachment; filename="%s.zip"`, base)}}, nil
}

var exportAliasRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ExportCertificateVersion packages a version as a password-protected
// PKCS#12 or JKS file. Authorization is certs:read then keys:export (an
// export always touches the key, unlike download's key/combined parts), and
// the key export is audited (certificate.key_exported, format p12/jks)
// before any byte is returned, exactly like DownloadCertificateVersion's
// key-bearing parts. The password is validated here (length; JKS's own
// ASCII/6-character minimum surfaces through render.ErrPassword) but never
// logged, audited, put in a URL, or echoed back.
func (s *Server) ExportCertificateVersion(ctx context.Context, r gen.ExportCertificateVersionRequestObject) (gen.ExportCertificateVersionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	if _, err := authorize(ctx, authz.ActionKeysExport, &r.OrgId); err != nil {
		return nil, err
	}
	format := string(r.Body.Format)
	renderer, ok := render.For(format)
	if !ok || (format != "p12" && format != "jks") {
		return nil, unprocessable("format", fmt.Sprintf("unknown export format %q; valid: p12, jks", format))
	}
	if r.Body.Password == nil || *r.Body.Password == "" {
		return nil, unprocessable("password", "required")
	}
	password := *r.Body.Password
	if utf8.RuneCountInString(password) > 128 {
		return nil, unprocessable("password", "must be at most 128 characters")
	}
	opts := render.OutputOpts{Password: password}
	if r.Body.Alias != nil {
		if format != "jks" {
			return nil, unprocessable("alias", "only valid for jks")
		}
		if !exportAliasRE.MatchString(*r.Body.Alias) {
			return nil, unprocessable("alias", `must match ^[A-Za-z0-9._-]{1,64}$`)
		}
		opts.Alias = *r.Body.Alias
	}
	if r.Body.Encoding != nil {
		if format != "p12" {
			return nil, unprocessable("encoding", "only valid for p12")
		}
		enc := string(*r.Body.Encoding)
		if enc != "modern" && enc != "legacy" {
			return nil, unprocessable("encoding", fmt.Sprintf("unknown encoding %q; valid: modern, legacy", enc))
		}
		opts.Encoding = enc
	}
	c, err := s.d.Issuance.Store.GetCertificate(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	m, err := s.d.Certs.Material(ctx, c.ID, r.Vid, true)
	if err != nil {
		return nil, mapErr(err)
	}
	opts.BaseName = delivery.SafeName(c.Name)
	files, err := renderer.Render(m, opts)
	if err != nil {
		if errors.Is(err, render.ErrNoKey) {
			return nil, &HTTPError{Status: http.StatusNotFound, Title: "Not found", Detail: "this version has no stored private key"}
		}
		if errors.Is(err, render.ErrPassword) {
			return nil, unprocessable("password", err.Error())
		}
		// encoding is already validated above, and password/alias/format are
		// all valid at this point, so anything else here is unexpected —
		// most likely corrupt stored leaf/chain DER — not caller error.
		return nil, err
	}
	org := r.OrgId
	if err := s.d.Auditor.Record(ctx, audit.Event{Action: "certificate.key_exported", ResourceType: "certificate_version",
		ResourceID: r.Vid.String(), OrgID: &org, Details: map[string]any{"certificateId": c.ID.String(), "format": format}}); err != nil {
		return nil, fmt.Errorf("audit key export: %w", err)
	}
	f := files[0]
	headers := gen.ExportCertificateVersion200ResponseHeaders{ContentDisposition: fmt.Sprintf(`attachment; filename="%s"`, f.Name)}
	if format == "p12" {
		return gen.ExportCertificateVersion200ApplicationxPkcs12Response{Body: bytes.NewReader(f.Data), ContentLength: int64(len(f.Data)), Headers: headers}, nil
	}
	return gen.ExportCertificateVersion200ApplicationxJavaKeystoreResponse{Body: bytes.NewReader(f.Data), ContentLength: int64(len(f.Data)), Headers: headers}, nil
}

// ListManualDNS returns the TXT records an operator must add for a waiting
// manual-dns attempt; empty when none is waiting.
func (s *Server) ListManualDNS(ctx context.Context, r gen.ListManualDNSRequestObject) (gen.ListManualDNSResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	recs, err := s.d.Issuance.Store.ManualPending(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make(gen.ListManualDNS200JSONResponse, len(recs))
	for i, m := range recs {
		out[i] = gen.ManualDNSRecord{Name: m.Name, Type: gen.ManualDNSRecordType("TXT"), Value: m.Value, Ttl: m.TTL, ExpiresAt: ptr(m.ExpiresAt)}
	}
	return out, nil
}

// ConfirmManualDNS resumes a waiting manual-dns attempt. 409 when nothing is
// waiting, including when the pending records were already dropped by a
// manual-dns timeout; that does not fail the attempt again here, since the
// timeout path already recorded its own failure.
func (s *Server) ConfirmManualDNS(ctx context.Context, r gen.ConfirmManualDNSRequestObject) (gen.ConfirmManualDNSResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsIssue, &r.OrgId); err != nil {
		return nil, err
	}
	n, err := s.d.Issuance.Store.ConfirmManual(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	if n == 0 {
		return nil, &HTTPError{Status: http.StatusConflict, Title: "Nothing to confirm", Detail: "no manual-dns records are waiting, or they expired"}
	}
	s.audit(ctx, audit.Event{Action: "certificate.manual_dns_confirmed", ResourceType: "certificate", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"confirmed": int(n)}})
	return gen.ConfirmManualDNS202JSONResponse{Confirmed: int(n)}, nil
}
