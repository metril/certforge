//go:build integration

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/api/gen"
)

// TestPeekTLS covers the chain lookup: 403 without delivery:write or
// cas:write, loopback refused until the notifications setting allows it, the
// presented chain returned (unverified, since the test CA is not a system
// root), a dead port as ok false, a bad url as 422, and the audit row.
func TestPeekTLS(t *testing.T) {
	f := newAPIFixture(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	peek := func(role, url string) (gen.TlsPeekResult, error) {
		res, err := f.srv.PeekTLS(f.as(role), gen.PeekTLSRequestObject{OrgId: f.org, Body: &gen.TlsPeekRequest{Url: url}})
		if err != nil {
			return gen.TlsPeekResult{}, err
		}
		return gen.TlsPeekResult(res.(gen.PeekTLS200JSONResponse)), nil
	}

	_, err := peek("viewer", srv.URL)
	wantStatus(t, err, http.StatusForbidden)
	_, err = peek("operator", srv.URL)
	wantStatus(t, err, http.StatusUnprocessableEntity)

	if err := f.settingsStore.Set(context.Background(), "section.notifications", map[string]any{"allowLoopbackUrls": true}); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{srv.URL, strings.TrimPrefix(srv.URL, "https://")} {
		out, err := peek("operator", in)
		if err != nil || !out.Ok || len(out.Chain) != 1 || out.Verified {
			t.Fatalf("%s: %+v %v", in, out, err)
		}
		c := out.Chain[0]
		if !strings.HasPrefix(c.Pem, "-----BEGIN CERTIFICATE-----") || strings.Count(c.Sha256, ":") != 31 || c.Sha256 != strings.ToUpper(c.Sha256) {
			t.Fatalf("bad cert: %+v", c)
		}
	}
	if out, err := peek("admin", "127.0.0.1:1"); err != nil || out.Ok || out.Error == nil || len(out.Chain) != 0 {
		t.Fatalf("dead port: %+v %v", out, err)
	}
	_, err = peek("admin", "http://x.example")
	wantStatus(t, err, http.StatusUnprocessableEntity)
	if f.auditCount(t, "tls.peek") == 0 {
		t.Fatal("no tls.peek audit rows")
	}
}
