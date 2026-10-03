//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

func TestOrgCRUD(t *testing.T) {
	e := newTestEnv(t)
	csrf, home := e.seedAdminSession()
	ctx := context.Background()
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"slug":"lab","name":"Lab"}`, http.StatusCreated},
		{`{"slug":"lab","name":"Lab 2"}`, http.StatusConflict},
		{`{"slug":"all","name":"All"}`, http.StatusUnprocessableEntity},
		{`{"slug":"Bad!","name":"x"}`, http.StatusUnprocessableEntity},
		{`{"slug":"ok","name":""}`, http.StatusUnprocessableEntity},
	} {
		if resp, out := e.doRaw(http.MethodPost, "/api/v1/orgs", "application/json", tc.body, csrf); resp.StatusCode != tc.want { //nolint:bodyclose // testEnv.doRaw closes the body
			t.Fatalf("%s: %d %s", tc.body, resp.StatusCode, out)
		}
	}
	lab, _ := e.deps.Queries.GetOrgBySlug(ctx, "lab")
	resp, out := e.do(http.MethodPatch, "/api/v1/orgs/"+lab.ID.String(), map[string]string{"name": "Laboratory"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(out), "Laboratory") {
		t.Fatalf("rename %d %s", resp.StatusCode, out)
	}
	if resp, _ := e.do(http.MethodPatch, "/api/v1/orgs/"+lab.ID.String(), map[string]string{"name": "x", "slug": "lab2"}, csrf); resp.StatusCode != http.StatusUnprocessableEntity { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("slug change %d", resp.StatusCode)
	}
	if _, err := e.deps.Pool.Exec(ctx, `INSERT INTO dns_provider_credentials (org_id, name, provider_code, secret_cfg) VALUES ($1, 'c', 'cloudflare', '\x00')`, lab.ID); err != nil {
		t.Fatal(err)
	}
	resp, out = e.do(http.MethodDelete, "/api/v1/orgs/"+lab.ID.String(), nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(out), "1 DNS credential") {
		t.Fatalf("delete with dependents %d %s", resp.StatusCode, out)
	}
	if _, err := e.deps.Pool.Exec(ctx, `DELETE FROM dns_provider_credentials WHERE org_id = $1`, lab.ID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.do(http.MethodDelete, "/api/v1/orgs/"+lab.ID.String(), nil, csrf); resp.StatusCode != http.StatusNoContent { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("delete %d", resp.StatusCode)
	}
	oa, oaCSRF, _ := e.userSession("olga", "org-admin", &home)
	if resp, _ := e.doClient(oa, http.MethodPost, "/api/v1/orgs", map[string]string{"slug": "x", "name": "X"}, http.Header{"X-Csrf-Token": {oaCSRF}}); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("org-admin create org %d", resp.StatusCode)
	}

	// A site also blocks the delete (controller ruling: sites count as a
	// user-created dependent, unlike issuance defaults and revoked keys).
	withSite, err := e.deps.Queries.CreateOrg(ctx, sqlcgenOrg("with-site"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Queries.CreateSite(ctx, sqlcgen.CreateSiteParams{OrgID: withSite.ID, Name: "Berlin"}); err != nil {
		t.Fatal(err)
	}
	if resp, out := e.do(http.MethodDelete, "/api/v1/orgs/"+withSite.ID.String(), nil, csrf); resp.StatusCode != http.StatusConflict || !strings.Contains(string(out), "1 site") { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("delete with site %d %s", resp.StatusCode, out)
	}

	// Notification channels and monitors cascade off the org row, but they
	// are user-created, so they block the delete too.
	withOps, err := e.deps.Queries.CreateOrg(ctx, sqlcgenOrg("with-ops"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Pool.Exec(ctx, `INSERT INTO notification_channels (org_id, name, type, config) VALUES ($1, 'ch', 'webhook', '{}')`, withOps.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Pool.Exec(ctx, `INSERT INTO external_monitors (org_id, name, host) VALUES ($1, 'mon', 'example.test')`, withOps.ID); err != nil {
		t.Fatal(err)
	}
	if resp, out := e.do(http.MethodDelete, "/api/v1/orgs/"+withOps.ID.String(), nil, csrf); resp.StatusCode != http.StatusConflict || !strings.Contains(string(out), "1 notification channel") || !strings.Contains(string(out), "1 monitor") { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("delete with channel and monitor %d %s", resp.StatusCode, out)
	}

	// An org whose only rows are its own issuance defaults and a revoked API
	// key deletes cleanly; both cascade off the org row.
	cleanup, err := e.deps.Queries.CreateOrg(ctx, sqlcgenOrg("cleanup"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Pool.Exec(ctx, `INSERT INTO issuance_defaults (org_id, config) VALUES ($1, '{}')`, cleanup.ID); err != nil {
		t.Fatal(err)
	}
	var adminID string
	if err := e.deps.Pool.QueryRow(ctx, `SELECT id FROM users LIMIT 1`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Pool.Exec(ctx,
		`INSERT INTO api_keys (name, prefix, secret_hash, scopes, org_id, created_by, revoked_at) VALUES ('k', 'abcdef012345', '\x00', '{admin}', $1, $2, now())`,
		cleanup.ID, adminID); err != nil {
		t.Fatal(err)
	}
	if resp, out := e.do(http.MethodDelete, "/api/v1/orgs/"+cleanup.ID.String(), nil, csrf); resp.StatusCode != http.StatusNoContent { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("delete with only cascading rows %d %s", resp.StatusCode, out)
	}
	var remaining int
	if err := e.deps.Pool.QueryRow(ctx, `SELECT count(*) FROM issuance_defaults WHERE org_id = $1`, cleanup.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("issuance_defaults row survived org delete")
	}
	if err := e.deps.Pool.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE org_id = $1`, cleanup.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("api_keys row survived org delete")
	}
}

func TestSites(t *testing.T) {
	e := newTestEnv(t)
	csrf, home := e.seedAdminSession()
	oa, oaCSRF, _ := e.userSession("olga", "org-admin", &home)
	viewer, vCSRF, _ := e.userSession("vic", "viewer", &home)
	base := "/api/v1/orgs/" + home.String() + "/sites"
	h := http.Header{"X-Csrf-Token": {oaCSRF}}
	resp, out := e.doClient(oa, http.MethodPost, base, map[string]string{"name": "Berlin"}, h) //nolint:bodyclose // doClient closes the body
	var site struct{ ID string }
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(out, &site) != nil {
		t.Fatalf("create %d %s", resp.StatusCode, out)
	}
	if resp, _ := e.doClient(oa, http.MethodPost, base, map[string]string{"name": "Berlin"}, h); resp.StatusCode != http.StatusConflict { //nolint:bodyclose // doClient closes the body
		t.Fatalf("duplicate %d", resp.StatusCode)
	}
	if resp, out := e.doClient(viewer, http.MethodGet, base, nil, nil); resp.StatusCode != http.StatusOK || !strings.Contains(string(out), "Berlin") { //nolint:bodyclose // doClient closes the body
		t.Fatalf("viewer list %d %s", resp.StatusCode, out)
	}
	if resp, _ := e.doClient(viewer, http.MethodPost, base, map[string]string{"name": "Paris"}, http.Header{"X-Csrf-Token": {vCSRF}}); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("viewer create %d", resp.StatusCode)
	}
	if resp, out := e.doClient(oa, http.MethodPatch, base+"/"+site.ID, map[string]string{"name": "Berlin HQ"}, h); resp.StatusCode != http.StatusOK || !strings.Contains(string(out), "Berlin HQ") { //nolint:bodyclose // doClient closes the body
		t.Fatalf("rename %d %s", resp.StatusCode, out)
	}
	lab, _ := e.deps.Queries.CreateOrg(context.Background(), sqlcgenOrg("lab"))
	if resp, _ := e.do(http.MethodDelete, "/api/v1/orgs/"+lab.ID.String()+"/sites/"+site.ID, nil, csrf); resp.StatusCode != http.StatusNotFound { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("delete through another org's path: %d", resp.StatusCode)
	}
	if _, err := e.deps.Pool.Exec(context.Background(), `INSERT INTO clients (org_id, site_id, name) VALUES ($1, $2, 'c1')`, home, site.ID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.doClient(oa, http.MethodDelete, base+"/"+site.ID, nil, h); resp.StatusCode != http.StatusNoContent { //nolint:bodyclose // doClient closes the body
		t.Fatalf("delete %d", resp.StatusCode)
	}
	if e.auditCount(t, "site.delete") != 1 {
		t.Fatal("site.delete not audited")
	}
	var details string
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT details::text FROM audit_events WHERE action = 'site.delete'`).Scan(&details); err != nil || !strings.Contains(details, `"detachedClients": 1`) {
		t.Fatalf("audit details %s err %v", details, err)
	}

	// olga is org-admin in home only; writing to lab's sites is forbidden.
	labBase := "/api/v1/orgs/" + lab.ID.String() + "/sites"
	if resp, _ := e.doClient(oa, http.MethodPost, labBase, map[string]string{"name": "Paris"}, h); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("org-admin cross-org create %d", resp.StatusCode)
	}
}

func sqlcgenOrg(slug string) sqlcgen.CreateOrgParams {
	return sqlcgen.CreateOrgParams{Slug: slug, Name: slug}
}
