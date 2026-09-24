//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/meta"
)

func TestListOrgs(t *testing.T) {
	e := newTestEnv(t)
	_, orgID := e.seedAdminSession()
	resp, body := e.do(http.MethodGet, "/api/v1/orgs", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code %d %s", resp.StatusCode, body)
	}
	var out struct {
		Items []struct{ ID, Slug string } `json:"items"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Items) != 1 {
		t.Fatalf("body %s", body)
	}
	if !strings.EqualFold(out.Items[0].ID, orgID.String()) || out.Items[0].Slug != "home" {
		t.Fatalf("org %+v", out.Items[0])
	}
}

func TestMetaSchemas(t *testing.T) {
	e := newTestEnv(t)
	e.seedAdminSession()
	resp, body := e.do(http.MethodGet, "/api/v1/meta/schemas", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"dnsProviders":[]`) {
		t.Fatalf("code %d body %s", resp.StatusCode, body)
	}
	e.deps.Meta.Add(meta.KindDNSProvider, meta.Entry{Code: "cloudflare", Name: "Cloudflare", Schema: json.RawMessage(`{"type":"object"}`)})
	_, body = e.do(http.MethodGet, "/api/v1/meta/schemas", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if !strings.Contains(string(body), `"code":"cloudflare"`) {
		t.Fatalf("body %s", body)
	}
}
