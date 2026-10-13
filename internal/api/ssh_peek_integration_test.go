//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
)

// TestPeekSSHHostKey covers 403 without delivery:write, loopback refused until
// allowed, a dead port as ok false, the host key returned, and the audit row.
func TestPeekSSHHostKey(t *testing.T) {
	f := newAPIFixture(t)
	srv := sshxtest.Start(t, nil)
	port := srv.Port(t)
	peek := func(role, host string, port int) (gen.SshPeekResult, error) {
		res, err := f.srv.PeekSSHHostKey(f.as(role), gen.PeekSSHHostKeyRequestObject{OrgId: f.org, Body: &gen.SshPeekRequest{Host: host, Port: &port}})
		if err != nil {
			return gen.SshPeekResult{}, err
		}
		return gen.SshPeekResult(res.(gen.PeekSSHHostKey200JSONResponse)), nil
	}
	_, err := peek("viewer", "127.0.0.1", port)
	wantStatus(t, err, http.StatusForbidden)
	_, err = peek("operator", "127.0.0.1", port)
	wantStatus(t, err, http.StatusUnprocessableEntity)
	_, err = peek("operator", " ", port)
	wantStatus(t, err, http.StatusUnprocessableEntity)
	_, err = peek("operator", "127.0.0.1", 70000)
	wantStatus(t, err, http.StatusUnprocessableEntity)

	if err := f.settingsStore.Set(context.Background(), "section.notifications", map[string]any{"allowLoopbackUrls": true}); err != nil {
		t.Fatal(err)
	}
	out, err := peek("operator", "127.0.0.1", port)
	if err != nil || !out.Ok || len(out.Keys) == 0 || out.Keys[0].Type != "ssh-ed25519" || out.Keys[0].Sha256 == "" {
		t.Fatalf("keys: %+v %v", out, err)
	}
	if out, err := peek("admin", "127.0.0.1", 1); err != nil || out.Ok || out.Error == nil || len(out.Keys) != 0 {
		t.Fatalf("dead port: %+v %v", out, err)
	}
	if f.auditCount(t, "ssh.peek") == 0 {
		t.Fatal("no ssh.peek audit rows")
	}
}
