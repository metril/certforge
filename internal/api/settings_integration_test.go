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

func TestSettingsGetPut(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()

	resp, body := e.do(http.MethodGet, "/api/v1/settings/general", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get %d %s", resp.StatusCode, body)
	}
	var sec struct {
		Section string          `json:"section"`
		Schema  map[string]any  `json:"schema"`
		Value   map[string]any  `json:"value"`
		Stored  *map[string]any `json:"stored"`
	}
	if err := json.Unmarshal(body, &sec); err != nil || sec.Section != "general" || sec.Schema["type"] != "object" || len(sec.Value) != 0 {
		t.Fatalf("section %s", body)
	}
	// Additive `stored` (controller ruling, review fix round 1): nil before
	// the section is ever saved, even though `value` already shows a
	// concrete (here empty, but for issuance_defaults built-in) display value.
	if sec.Stored != nil {
		t.Fatalf("stored should be null before any save, got %v", *sec.Stored)
	}

	resp, body = e.do(http.MethodPut, "/api/v1/settings/general", map[string]string{"baseUrl": "https://certs.example.com"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "https://certs.example.com") {
		t.Fatalf("put %d %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &sec); err != nil || sec.Stored == nil || (*sec.Stored)["baseUrl"] != "https://certs.example.com" {
		t.Fatalf("stored should equal value once saved: %s", body)
	}
	resp, body = e.do(http.MethodPut, "/api/v1/settings/general", map[string]string{"baseUrl": "ftp://nope"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnprocessableEntity || resp.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("invalid put %d %s", resp.StatusCode, body)
	}
	if resp, _ = e.do(http.MethodGet, "/api/v1/settings/nope", nil, ""); resp.StatusCode != http.StatusNotFound { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("unknown section %d", resp.StatusCode)
	}
	resp, _ = e.doRaw(http.MethodPut, "/api/v1/settings/general", "text/plain", `{"baseUrl":"https://x.example"}`, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain %d", resp.StatusCode)
	}

	evs, err := e.deps.Queries.ListAuditEventsAsc(context.Background(), sqlcgen.ListAuditEventsAscParams{ID: 0, Limit: 10})
	if err != nil || len(evs) != 1 || evs[0].Action != "settings.update" {
		t.Fatalf("audit %+v err %v", evs, err)
	}
}

func TestSettingsSecretField(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	e.deps.Sections.MustRegister("test_secret", json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
	  "issuer":{"type":"string","description":"Issuer."},"clientSecret":{"type":"string","secret":true,"description":"Secret."}}}`), json.RawMessage(`{}`))

	resp, body := e.do(http.MethodPut, "/api/v1/settings/test_secret", map[string]string{"issuer": "a", "clientSecret": "__unchanged__"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unchanged with nothing stored: %d %s", resp.StatusCode, body)
	}
	resp, body = e.do(http.MethodPut, "/api/v1/settings/test_secret", map[string]string{"issuer": "a", "clientSecret": "s3cret"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "s3cret") {
		t.Fatalf("put %d %s", resp.StatusCode, body)
	}
	var sec struct {
		Value         map[string]any `json:"value"`
		StoredSecrets []string       `json:"storedSecrets"`
	}
	if err := json.Unmarshal(body, &sec); err != nil || len(sec.StoredSecrets) != 1 || sec.StoredSecrets[0] != "clientSecret" {
		t.Fatalf("storedSecrets %s", body)
	}
	if _, ok := sec.Value["clientSecret"]; ok {
		t.Fatalf("value holds secret: %s", body)
	}
	var details string
	if err := e.deps.Pool.QueryRow(context.Background(),
		`SELECT details::text FROM audit_events WHERE action = 'settings.update' ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "s3cret") || !strings.Contains(details, `"secretsChanged": ["clientSecret"]`) {
		t.Fatalf("audit details %s", details)
	}
}

func TestSettingsCSRF(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	resp, _ := e.do(http.MethodPut, "/api/v1/settings/general", map[string]string{"baseUrl": "https://evil.example"}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no csrf %d", resp.StatusCode)
	}
	resp, _ = e.do(http.MethodPut, "/api/v1/settings/general", map[string]string{"baseUrl": "https://evil.example"}, csrf+"x") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad csrf %d", resp.StatusCode)
	}
	_, body := e.do(http.MethodGet, "/api/v1/settings/general", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if strings.Contains(string(body), "evil.example") {
		t.Fatal("value changed without CSRF token")
	}
}
