//go:build integration

package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestUploadBodyTooLarge is the Task 13 brief's coverage that
// uploadCertificate inherits the global 1 MiB request body cap
// (requireJSON's http.MaxBytesReader): the strict server's JSON decode
// hits the limit before the handler ever runs, so this needs no
// api.Deps.Issuance wiring — a real HTTP round trip through the router's
// auth and body-limit middleware, same as TestBodyTooLarge (router_test.go)
// at another route, is enough on its own.
func TestUploadBodyTooLarge(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	big := `{"name":"big","certificatePem":"` + strings.Repeat("a", 2<<20) + `"}`
	resp, body := e.doRaw(http.MethodPost, "/api/v1/orgs/"+org.String()+"/certificates/upload", "application/json", big, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
}
