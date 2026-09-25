package api

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// maxAuditExportRows caps GET /audit/export; the caller is told via
// X-Audit-Truncated when the cap was hit.
const maxAuditExportRows = 100_000

// auditExportPage is the chunk size ExportAuditEvents fetches at a time.
const auditExportPage = 1000

type auditFilter struct {
	from, to                                   *time.Time
	actor, action, resourceType, resourceID, q string
	anyOrg                                     bool
	orgIDs                                     []uuid.UUID
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

// auditScope limits the query to what the caller may read: with global
// audit:read, everything; with an explicit orgId, that org (403 unless the
// caller has audit:read there); otherwise every org the caller has
// audit:read in (global events are hidden), 403 if that set is empty.
func auditScope(ctx context.Context, orgID *uuid.UUID) (anyOrg bool, orgIDs []uuid.UUID, err error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return false, nil, errUnauthenticated
	}
	forbidden := &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "missing permission audit:read"}
	if orgID != nil {
		if !authz.Can(p, authz.ActionAuditRead, orgID) {
			return false, nil, forbidden
		}
		return false, []uuid.UUID{*orgID}, nil
	}
	if authz.Can(p, authz.ActionAuditRead, nil) {
		return true, []uuid.UUID{}, nil
	}
	orgs := authz.OrgsWith(p, authz.ActionAuditRead)
	if len(orgs) == 0 {
		return false, nil, forbidden
	}
	return false, orgs, nil
}

func newAuditFilter(ctx context.Context, from, to *time.Time, actor, action, rtype, rid *string, orgID *uuid.UUID, q *string) (auditFilter, error) {
	anyOrg, orgs, err := auditScope(ctx, orgID)
	if err != nil {
		return auditFilter{}, err
	}
	return auditFilter{from: from, to: to, actor: deref(actor), action: deref(action), resourceType: deref(rtype),
		resourceID: deref(rid), q: deref(q), anyOrg: anyOrg, orgIDs: orgs}, nil
}

func (f auditFilter) params(beforeID int64, hasCursor bool, limit int) sqlcgen.ListAuditEventsParams {
	p := sqlcgen.ListAuditEventsParams{Actor: f.actor, Action: f.action, ResourceType: f.resourceType, ResourceID: f.resourceID,
		AnyOrg: f.anyOrg, OrgIds: f.orgIDs, Q: f.q, HasCursor: hasCursor, BeforeID: beforeID, PageLimit: int32(limit)}
	if f.from != nil {
		p.HasFrom, p.FromTs = true, *f.from
	}
	if f.to != nil {
		p.HasTo, p.ToTs = true, *f.to
	}
	return p
}

func (f auditFilter) countParams(limit int) sqlcgen.CountAuditEventsCappedParams {
	p := sqlcgen.CountAuditEventsCappedParams{Actor: f.actor, Action: f.action, ResourceType: f.resourceType, ResourceID: f.resourceID,
		AnyOrg: f.anyOrg, OrgIds: f.orgIDs, Q: f.q, PageLimit: int32(limit)}
	if f.from != nil {
		p.HasFrom, p.FromTs = true, *f.from
	}
	if f.to != nil {
		p.HasTo, p.ToTs = true, *f.to
	}
	return p
}

func auditOut(r sqlcgen.ListAuditEventsRow) (gen.AuditEvent, error) {
	details := map[string]interface{}{}
	if err := json.Unmarshal(r.Details, &details); err != nil {
		return gen.AuditEvent{}, err
	}
	return gen.AuditEvent{Id: r.ID, Ts: r.Ts, ActorType: r.ActorType, ActorId: r.ActorID, ActorName: r.ActorName, Action: r.Action,
		ResourceType: r.ResourceType, ResourceId: r.ResourceID, OrgId: r.OrgID, Ip: r.Ip, Details: details}, nil
}

// ListAuditEvents returns one page of events, newest first.
func (s *Server) ListAuditEvents(ctx context.Context, req gen.ListAuditEventsRequestObject) (gen.ListAuditEventsResponseObject, error) {
	pr := req.Params
	f, err := newAuditFilter(ctx, pr.From, pr.To, pr.Actor, pr.Action, pr.ResourceType, pr.ResourceId, pr.OrgId, pr.Q)
	if err != nil {
		return nil, err
	}
	limit := 50
	if pr.Limit != nil {
		if *pr.Limit < 1 || *pr.Limit > 500 {
			return nil, unprocessable("limit", "limit must be 1..500")
		}
		limit = *pr.Limit
	}
	var before int64
	hasCursor := pr.Cursor != nil && *pr.Cursor != ""
	if hasCursor {
		b, err := base64.RawURLEncoding.DecodeString(*pr.Cursor)
		if err == nil {
			before, err = strconv.ParseInt(string(b), 10, 64)
		}
		if err != nil || before <= 0 {
			return nil, badRequest("cursor is not from this list")
		}
	}
	rows, err := s.d.Queries.ListAuditEvents(ctx, f.params(before, hasCursor, limit+1))
	if err != nil {
		return nil, err
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		c := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(rows[limit-1].ID, 10)))
		next = &c
	}
	items := make([]gen.AuditEvent, 0, len(rows))
	for _, r := range rows {
		ev, err := auditOut(r)
		if err != nil {
			return nil, err
		}
		items = append(items, ev)
	}
	return gen.ListAuditEvents200JSONResponse(gen.AuditEventList{Items: items, NextCursor: next}), nil
}

// csvCell stops a spreadsheet from evaluating a cell as a formula: any
// value starting with =, +, -, @, a tab or a carriage return gets a
// leading apostrophe, which every spreadsheet treats as "force text" and
// every CSV parser treats as ordinary data.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

var auditCSVHeader = []string{"id", "ts", "actor_type", "actor_id", "actor_name", "action", "resource_type", "resource_id", "org_id", "ip", "details"}

// auditCSVRow renders one queried row as its export.csv row, with formula
// neutralization applied to every cell.
func auditCSVRow(r sqlcgen.ListAuditEventsRow) []string {
	org := ""
	if r.OrgID != nil {
		org = r.OrgID.String()
	}
	rec := []string{strconv.FormatInt(r.ID, 10), r.Ts.UTC().Format(time.RFC3339Nano), r.ActorType, r.ActorID, r.ActorName,
		r.Action, r.ResourceType, r.ResourceID, org, r.Ip, string(r.Details)}
	for i := range rec {
		rec[i] = csvCell(rec[i])
	}
	return rec
}

// auditRowFetcher returns the next page of rows strictly before beforeID
// (ordered newest first), or the first page when !hasCursor.
type auditRowFetcher func(ctx context.Context, beforeID int64, hasCursor bool, limit int) ([]sqlcgen.ListAuditEventsRow, error)

// writeAuditCSV streams up to cap rows from fetch as CSV, fetching page
// rows at a time. A fetch error partway through does not truncate the file
// silently: a final "#error,<message>" row is written instead, so the
// output is visibly incomplete rather than just short.
func writeAuditCSV(ctx context.Context, w io.Writer, fetch auditRowFetcher, capRows, page int) {
	cw := csv.NewWriter(w)
	_ = cw.Write(auditCSVHeader)
	var before int64
	has, n := false, 0
	for n < capRows {
		limit := page
		if capRows-n < limit {
			limit = capRows - n
		}
		rows, err := fetch(ctx, before, has, limit)
		if err != nil {
			_ = cw.Write([]string{"#error", err.Error()})
			break
		}
		for _, r := range rows {
			_ = cw.Write(auditCSVRow(r))
			n++
		}
		if len(rows) < limit {
			break
		}
		before, has = rows[len(rows)-1].ID, true
	}
	cw.Flush()
}

// ExportAuditEvents streams the filtered events as CSV. Whether the cap
// will truncate the result is decided up front with a bounded count, so
// X-Audit-Truncated can be set before the body starts streaming; the export
// itself is recorded as audit.export before any row is sent.
func (s *Server) ExportAuditEvents(ctx context.Context, req gen.ExportAuditEventsRequestObject) (gen.ExportAuditEventsResponseObject, error) {
	pr := req.Params
	f, err := newAuditFilter(ctx, pr.From, pr.To, pr.Actor, pr.Action, pr.ResourceType, pr.ResourceId, pr.OrgId, pr.Q)
	if err != nil {
		return nil, err
	}
	capped, err := s.d.Queries.CountAuditEventsCapped(ctx, f.countParams(maxAuditExportRows+1))
	if err != nil {
		return nil, err
	}
	truncated := capped > maxAuditExportRows
	s.audit(ctx, audit.Event{Action: "audit.export", ResourceType: "audit", OrgID: pr.OrgId,
		Details: map[string]any{"from": pr.From, "to": pr.To, "actor": f.actor, "action": f.action,
			"resourceType": f.resourceType, "resourceId": f.resourceID, "q": f.q, "truncated": truncated}})
	pr2, pw := io.Pipe()
	go func() {
		writeAuditCSV(ctx, pw, func(ctx context.Context, before int64, has bool, limit int) ([]sqlcgen.ListAuditEventsRow, error) {
			return s.d.Queries.ListAuditEvents(ctx, f.params(before, has, limit))
		}, maxAuditExportRows, auditExportPage)
		_ = pw.Close()
	}()
	name := fmt.Sprintf(`attachment; filename="audit-%s.csv"`, time.Now().UTC().Format("2006-01-02"))
	return gen.ExportAuditEvents200TextcsvResponse{Body: pr2, Headers: gen.ExportAuditEvents200ResponseHeaders{
		ContentDisposition: name, XAuditTruncated: truncated}}, nil
}

// VerifyAuditChain walks the chain, caching the result for
// Deps.AuditVerifyTTL (0 means 60 s). Needs audit:read somewhere (global or
// in any org): chain status is not org-scoped, so any auditor may ask.
func (s *Server) VerifyAuditChain(ctx context.Context, _ gen.VerifyAuditChainRequestObject) (gen.VerifyAuditChainResponseObject, error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	if !authz.Can(p, authz.ActionAuditRead, nil) && len(authz.OrgsWith(p, authz.ActionAuditRead)) == 0 {
		return nil, &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "missing permission audit:read"}
	}
	ttl := s.d.AuditVerifyTTL
	if ttl == 0 {
		ttl = time.Minute
	}
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	if time.Since(s.verifyAt) < ttl {
		return gen.VerifyAuditChain200JSONResponse(s.verifyRes), nil
	}
	r, err := s.d.Auditor.Check(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.AuditChainStatus{Ok: r.OK, Count: r.Count, CheckedAt: time.Now().UTC(), HeadHash: hex.EncodeToString(r.HeadHash)}
	if !r.OK {
		out.BrokenAtId = &r.BrokenAtID
	}
	s.verifyAt, s.verifyRes = time.Now(), out
	return gen.VerifyAuditChain200JSONResponse(out), nil
}
