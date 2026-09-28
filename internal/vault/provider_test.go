package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/settings"
)

// fakeSettingsSource is a settingsSource test double: value/stored/secrets
// are read fresh on every call, so a test can mutate them between calls to
// Provider.Client/Test without a database.
type fakeSettingsSource struct {
	value   json.RawMessage
	secrets map[string]string
}

func (f *fakeSettingsSource) GetSection(context.Context, *settings.Section) (json.RawMessage, json.RawMessage, error) {
	return f.value, f.value, nil
}

func (f *fakeSettingsSource) SectionSecrets(context.Context, *settings.Section) (map[string]string, error) {
	return f.secrets, nil
}

func testVaultSection(t *testing.T) *settings.Section {
	t.Helper()
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, ok := r.Section(SectionName)
	if !ok {
		t.Fatal("vault section not registered")
	}
	return sec
}

func approleFake(t *testing.T) *fakeVault {
	t.Helper()
	fv := newFakeVault()
	fv.handle(http.MethodPost, "/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": "leased-token", "lease_duration": 3600, "renewable": true}})
	})
	fv.handle(http.MethodGet, "/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ttl": 3600, "policies": []string{"default"}, "renewable": true}})
	})
	return fv
}

// TestProviderCachesPerRevision covers Client's cache: unchanged settings
// return the same *Client without logging in again; a change to the
// section's secrets (here secretId) rebuilds and re-logs in, and the old
// client's renewal loop is closed.
func TestProviderCachesPerRevision(t *testing.T) {
	fv := approleFake(t)
	defer fv.Close()

	src := &fakeSettingsSource{
		value:   json.RawMessage(`{"address":"` + fv.URL() + `","authMethod":"approle","roleId":"r1"}`),
		secrets: map[string]string{"secretId": "s1"},
	}
	p := &Provider{store: src, sec: testVaultSection(t)}
	ctx := context.Background()

	c1, err := p.Client(ctx)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if got := fv.CallCount(http.MethodPost, "/v1/auth/approle/login"); got != 1 {
		t.Fatalf("login calls = %d, want 1", got)
	}

	c2, err := p.Client(ctx)
	if err != nil {
		t.Fatalf("Client (cached): %v", err)
	}
	if c2 != c1 {
		t.Fatal("unchanged settings must return the cached client")
	}
	if got := fv.CallCount(http.MethodPost, "/v1/auth/approle/login"); got != 1 {
		t.Fatalf("login calls after cache hit = %d, want 1", got)
	}

	src.secrets = map[string]string{"secretId": "s2"}
	c3, err := p.Client(ctx)
	if err != nil {
		t.Fatalf("Client (changed secret): %v", err)
	}
	defer c3.Close()
	if c3 == c1 {
		t.Fatal("changed secretId must rebuild the client")
	}
	if got := fv.CallCount(http.MethodPost, "/v1/auth/approle/login"); got != 2 {
		t.Fatalf("login calls after rebuild = %d, want 2", got)
	}
}

// TestVaultTestUsesStoredSecrets covers Test's merge: raw omits token, so
// the section's currently stored secret is used to actually reach Vault.
func TestVaultTestUsesStoredSecrets(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodGet, "/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"initialized": true, "sealed": false, "version": "1.18.0"})
	})
	fv.handle(http.MethodGet, "/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ttl": 120, "policies": []string{"default"}, "renewable": false}})
	})

	src := &fakeSettingsSource{secrets: map[string]string{"token": "stored-token"}}
	p := &Provider{store: src, sec: testVaultSection(t)}

	raw := json.RawMessage(`{"address":"` + fv.URL() + `","authMethod":"token"}`)
	res := p.Test(context.Background(), raw)
	if !res.OK || res.TokenTTLSeconds != 120 {
		t.Fatalf("result = %+v", res)
	}
	if got := fv.LastHeader(http.MethodGet, "/v1/auth/token/lookup-self", "X-Vault-Token"); got != "stored-token" {
		t.Fatalf("X-Vault-Token = %q, want the stored token", got)
	}
}

// TestVaultTestScrubsSecrets covers Test's extra scrub pass over raw: an
// error that echoes back a field Client.Redact does not itself know about
// (roleId; Redact only tracks the client's own token/secretId) must still
// come back with that value removed.
func TestVaultTestScrubsSecrets(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodPost, "/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 400, map[string]any{"errors": []string{`invalid role_id "role-XYZ-secret"`}})
	})

	src := &fakeSettingsSource{}
	p := &Provider{store: src, sec: testVaultSection(t)}

	raw := json.RawMessage(`{"address":"` + fv.URL() + `","authMethod":"approle","roleId":"role-XYZ-secret","secretId":"s3"}`)
	res := p.Test(context.Background(), raw)
	if res.OK {
		t.Fatal("expected a login failure")
	}
	if strings.Contains(res.Error, "role-XYZ-secret") {
		t.Fatalf("error leaks roleId: %s", res.Error)
	}
	if strings.Contains(res.Error, "s3") {
		t.Fatalf("error leaks secretId: %s", res.Error)
	}
}
