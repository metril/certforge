//go:build integration

package api_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/audit"
)

type auditPage struct {
	Items []struct {
		ID        int64   `json:"id"`
		Action    string  `json:"action"`
		ActorName string  `json:"actorName"`
		OrgID     *string `json:"orgId"`
	} `json:"items"`
	NextCursor *string `json:"nextCursor"`
}

func getAudit(t *testing.T, e *testEnv, c *http.Client, query string, want int) auditPage {
	t.Helper()
	resp, body := e.doClient(c, http.MethodGet, "/api/v1/audit?"+query, nil, nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != want {
		t.Fatalf("GET /audit?%s: %d %s", query, resp.StatusCode, body)
	}
	var p auditPage
	_ = json.Unmarshal(body, &p)
	return p
}

func TestAuditList(t *testing.T) {
	e := newTestEnv(t)
	csrf, home := e.seedAdminSession()
	for i := 0; i < 3; i++ {
		e.do(http.MethodPut, "/api/v1/settings/general", map[string]string{}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	}
	e.do(http.MethodPost, "/api/v1/orgs/"+home.String()+"/sites", map[string]string{"name": "Berlin"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body

	p1 := getAudit(t, e, e.client, "limit=2", http.StatusOK)
	if len(p1.Items) != 2 || p1.Items[0].Action != "site.create" || p1.NextCursor == nil || p1.Items[0].ID <= p1.Items[1].ID {
		t.Fatalf("page 1 %+v", p1)
	}
	p2 := getAudit(t, e, e.client, "limit=2&cursor="+url.QueryEscape(*p1.NextCursor), http.StatusOK)
	if len(p2.Items) != 2 || p2.Items[0].ID >= p1.Items[1].ID {
		t.Fatalf("page 2 %+v", p2)
	}
	if p := getAudit(t, e, e.client, "action=settings.update", http.StatusOK); len(p.Items) != 3 {
		t.Fatalf("exact action %d", len(p.Items))
	}
	if p := getAudit(t, e, e.client, "action=settings.", http.StatusOK); len(p.Items) != 3 {
		t.Fatalf("prefix action %d", len(p.Items))
	}
	if p := getAudit(t, e, e.client, "q=berlin", http.StatusOK); len(p.Items) != 1 || p.Items[0].ActorName != "Local admin" {
		t.Fatalf("q %+v", p)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if p := getAudit(t, e, e.client, "from="+url.QueryEscape(future), http.StatusOK); len(p.Items) != 0 {
		t.Fatalf("from future %d", len(p.Items))
	}
	if p := getAudit(t, e, e.client, "orgId="+home.String(), http.StatusOK); len(p.Items) != 1 {
		t.Fatalf("org filter %d", len(p.Items))
	}
	getAudit(t, e, e.client, "cursor=garbage", http.StatusBadRequest)
	getAudit(t, e, e.client, "limit=0", http.StatusUnprocessableEntity)
}

// A system or anonymous actor id is not a UUID; the actor joins must not try
// to cast it.
func TestAuditListNonUUIDActor(t *testing.T) {
	e := newTestEnv(t)
	e.seedAdminSession()
	ctx := context.Background()
	if err := e.deps.Auditor.Record(ctx, audit.Event{Action: "job.run", ResourceType: "job", ActorType: "system", ActorID: "system"}); err != nil {
		t.Fatal(err)
	}
	if err := e.deps.Auditor.Record(ctx, audit.Event{Action: "job.run", ResourceType: "job", ActorType: "user", ActorID: "not-a-uuid"}); err != nil {
		t.Fatal(err)
	}
	p := getAudit(t, e, e.client, "action=job.run", http.StatusOK)
	if len(p.Items) != 2 || p.Items[0].ActorName != "" || p.Items[1].ActorName != "" {
		t.Fatalf("non-uuid actors %+v", p)
	}
	getAudit(t, e, e.client, "q=system", http.StatusOK)
}

func TestAuditScope(t *testing.T) {
	e := newTestEnv(t)
	csrf, home := e.seedAdminSession()
	e.do(http.MethodPut, "/api/v1/settings/general", map[string]string{}, csrf)                              //nolint:bodyclose // testEnv.doRaw closes the body
	e.do(http.MethodPost, "/api/v1/orgs/"+home.String()+"/sites", map[string]string{"name": "Berlin"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	lab, _ := e.deps.Queries.CreateOrg(context.Background(), sqlcgenOrg("lab"))
	auditor, _, _ := e.userSession("aud", "auditor", &home)
	p := getAudit(t, e, auditor, "", http.StatusOK)
	if len(p.Items) == 0 {
		t.Fatalf("org auditor sees no events")
	}
	for _, it := range p.Items {
		if it.OrgID == nil || *it.OrgID != home.String() {
			t.Fatalf("org auditor sees %+v", it)
		}
	}
	getAudit(t, e, auditor, "orgId="+lab.ID.String(), http.StatusForbidden)
	viewer, _, _ := e.userSession("vic", "viewer", &home)
	getAudit(t, e, viewer, "", http.StatusForbidden)
	// Chain verification needs global audit:read: it covers every org (and
	// global events), so an org-scoped auditor is 403 even for their own org.
	if resp, _ := e.doClient(auditor, http.MethodGet, "/api/v1/audit/verify", nil, nil); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("org auditor verify %d, want 403", resp.StatusCode)
	}
}

// TestAuditGetEvent covers GET /audit/{id}: an org auditor can fetch an
// event in their own org, a null-org (global) event needs global
// audit:read, and both a missing id and one the caller may not see answer
// the same 404 (controller ruling C10 — no distinguishable 403).
func TestAuditGetEvent(t *testing.T) {
	e := newTestEnv(t)
	csrf, home := e.seedAdminSession()
	e.do(http.MethodPut, "/api/v1/settings/general", map[string]string{}, csrf)                              //nolint:bodyclose // testEnv.doRaw closes the body
	e.do(http.MethodPost, "/api/v1/orgs/"+home.String()+"/sites", map[string]string{"name": "Berlin"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	lab, _ := e.deps.Queries.CreateOrg(context.Background(), sqlcgenOrg("lab"))

	p := getAudit(t, e, e.client, "action=site.create&limit=1", http.StatusOK)
	if len(p.Items) != 1 {
		t.Fatalf("seed site.create %+v", p)
	}
	siteEventID := p.Items[0].ID
	pGlobal := getAudit(t, e, e.client, "action=settings.update&limit=1", http.StatusOK)
	if len(pGlobal.Items) != 1 || pGlobal.Items[0].OrgID != nil {
		t.Fatalf("seed settings.update (global) %+v", pGlobal)
	}
	globalEventID := pGlobal.Items[0].ID

	get := func(c *http.Client, id int64) (int, []byte) {
		resp, body := e.doClient(c, http.MethodGet, fmt.Sprintf("/api/v1/audit/%d", id), nil, nil) //nolint:bodyclose // doClient closes the body
		return resp.StatusCode, body
	}
	if status, body := get(e.client, siteEventID); status != http.StatusOK {
		t.Fatalf("admin get org event: %d %s", status, body)
	}
	if status, body := get(e.client, globalEventID); status != http.StatusOK {
		t.Fatalf("admin get global event: %d %s", status, body)
	}

	auditor, _, _ := e.userSession("aud", "auditor", &home)
	if status, _ := get(auditor, siteEventID); status != http.StatusOK {
		t.Fatalf("org auditor get own-org event: %d", status)
	}
	if status, body := get(auditor, globalEventID); status != http.StatusNotFound {
		t.Fatalf("org auditor get global event: %d %s", status, body)
	}

	labAuditor, _, _ := e.userSession("labaud", "auditor", &lab.ID)
	labStatus, labBody := get(labAuditor, siteEventID)
	if labStatus != http.StatusNotFound {
		t.Fatalf("other-org auditor get event: %d %s", labStatus, labBody)
	}
	missingStatus, missingBody := get(e.client, 999_999_999)
	if missingStatus != http.StatusNotFound {
		t.Fatalf("missing id: %d %s", missingStatus, missingBody)
	}
	// Same detail message whether the id doesn't exist or the caller may
	// not see it: a probe can't tell the two apart.
	var wrongOrg, missing struct {
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(labBody, &wrongOrg)
	_ = json.Unmarshal(missingBody, &missing)
	if wrongOrg.Detail == "" || wrongOrg.Detail != strings.Replace(missing.Detail, "999999999", strconv.FormatInt(siteEventID, 10), 1) {
		t.Fatalf("detail mismatch: wrongOrg=%q missing=%q", wrongOrg.Detail, missing.Detail)
	}

	viewer, _, _ := e.userSession("vic", "viewer", &home)
	if status, _ := get(viewer, siteEventID); status != http.StatusNotFound {
		t.Fatalf("viewer (no audit:read) get event: %d", status)
	}
	if status, _ := get(e.client, siteEventID); status != http.StatusOK {
		t.Fatalf("admin still gets event after other assertions: %d", status)
	}
}

func TestAuditExportNeutralizesFormulas(t *testing.T) {
	e := newTestEnv(t)
	_, home := e.seedAdminSession()
	evil, evilCSRF, _ := e.userSession("=SUM(1+1)", "org-admin", &home)
	e.doClient(evil, http.MethodPost, "/api/v1/orgs/"+home.String()+"/sites", map[string]string{"name": "x"}, http.Header{"X-Csrf-Token": {evilCSRF}}) //nolint:bodyclose // doClient closes the body
	resp, body := e.do(http.MethodGet, "/api/v1/audit/export?action=site.create", nil, "")                                                             //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/csv; charset=utf-8" ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "audit-") {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("X-Audit-Truncated") != "false" {
		t.Fatalf("X-Audit-Truncated: %q", resp.Header.Get("X-Audit-Truncated"))
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil || len(rows) != 2 || rows[0][4] != "actor_name" {
		t.Fatalf("csv %v %q", err, body)
	}
	if rows[1][4] != "'=SUM(1+1)" {
		t.Fatalf("actor_name cell %q", rows[1][4])
	}
	var n int
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'audit.export'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("export not audited: %d %v", n, err)
	}
}

// TestAuditExportCSVQuoting covers proper CSV quoting (Review Focus for
// this task): a name containing a comma, a double quote and an embedded
// newline must round-trip exactly through the exported CSV.
func TestAuditExportCSVQuoting(t *testing.T) {
	e := newTestEnv(t)
	_, home := e.seedAdminSession()
	const tricky = "Berlin, \"HQ\"\nSecond line"
	quoted, quotedCSRF, _ := e.userSession(tricky, "org-admin", &home)
	e.doClient(quoted, http.MethodPost, "/api/v1/orgs/"+home.String()+"/sites", map[string]string{"name": "y"}, http.Header{"X-Csrf-Token": {quotedCSRF}}) //nolint:bodyclose // doClient closes the body
	resp, body := e.do(http.MethodGet, "/api/v1/audit/export?action=site.create", nil, "")                                                                 //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v\n%s", err, body)
	}
	if len(rows) != 2 || rows[1][4] != tricky {
		t.Fatalf("actor_name cell %q, want %q (rows=%v)", rows[1][4], tricky, rows)
	}
}

func TestAuditVerify(t *testing.T) {
	e := newTestEnvOpts(t, func(d *api.Deps) { d.AuditVerifyTTL = time.Nanosecond })
	csrf, _ := e.seedAdminSession()
	e.do(http.MethodPut, "/api/v1/settings/general", map[string]string{}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	var st struct {
		Ok         bool   `json:"ok"`
		Count      int64  `json:"count"`
		BrokenAtID *int64  `json:"brokenAtId"`
		Reason     *string `json:"reason"`
		HeadID     *int64  `json:"headId"`
	}
	_, body := e.do(http.MethodGet, "/api/v1/audit/verify", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if json.Unmarshal(body, &st) != nil || !st.Ok || st.Count < 1 || st.BrokenAtID != nil || st.Reason != nil || st.HeadID == nil {
		t.Fatalf("verify %s", body)
	}
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		`UPDATE audit_events SET action = 'forged' WHERE id = (SELECT min(id) FROM audit_events)`,
		"ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable",
	} {
		if _, err := e.deps.Pool.Exec(context.Background(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	_, body = e.do(http.MethodGet, "/api/v1/audit/verify", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if json.Unmarshal(body, &st) != nil || st.Ok || st.BrokenAtID == nil || st.Reason == nil || *st.Reason != "row_mismatch" {
		t.Fatalf("tampered verify %s", body)
	}
}
