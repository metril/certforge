//go:build integration

package api_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api"
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
		BrokenAtID *int64 `json:"brokenAtId"`
	}
	_, body := e.do(http.MethodGet, "/api/v1/audit/verify", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if json.Unmarshal(body, &st) != nil || !st.Ok || st.Count < 1 || st.BrokenAtID != nil {
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
	if json.Unmarshal(body, &st) != nil || st.Ok || st.BrokenAtID == nil {
		t.Fatalf("tampered verify %s", body)
	}
}
