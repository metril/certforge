package targets_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/targetstest"
)

func newRegistry(t *testing.T, typ string, mode targets.Mode, policy targets.KeyPolicy) *targets.Registry {
	t.Helper()
	r := targets.NewRegistry()
	r.Register(&targetstest.Secret{Code: typ, Mode: mode, Policy: policy})
	return r
}

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	r := targets.NewRegistry()
	r.Register(&targetstest.Secret{Code: "dup", Mode: targets.Server, Policy: targets.Never})
	defer func() {
		if recover() == nil {
			t.Fatal("Register did not panic on a duplicate type")
		}
	}()
	r.Register(&targetstest.Secret{Code: "dup", Mode: targets.Server, Policy: targets.Never})
}

func TestEachIteratesSorted(t *testing.T) {
	r := targets.NewRegistry()
	r.Register(&targetstest.Secret{Code: "zzz", Mode: targets.Server, Policy: targets.Never})
	r.Register(&targetstest.Secret{Code: "aaa", Mode: targets.Server, Policy: targets.Never})
	r.Register(&targetstest.Secret{Code: "mmm", Mode: targets.Server, Policy: targets.Never})
	var got []string
	r.Each(func(t targets.Target) { got = append(got, t.Type()) })
	want := []string{"aaa", "mmm", "zzz"}
	if len(got) != len(want) {
		t.Fatalf("Each returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Each returned %v, want %v", got, want)
		}
	}
}

func TestParseUnchangedResolves(t *testing.T) {
	r := newRegistry(t, "secret-test", targets.Server, targets.Never)
	stored := map[string]string{"token": "stored-token", "note": "stored-note"}

	// token explicitly Unchanged, note omitted entirely: both are reused
	// the same way.
	cfg, reused, err := r.Parse("secret-test", json.RawMessage(`{"url":"https://example.test","token":"__unchanged__"}`), stored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Secrets["token"] != "stored-token" {
		t.Errorf("token = %q, want stored-token", cfg.Secrets["token"])
	}
	if len(reused) != 2 || reused[0] != "note" || reused[1] != "token" {
		t.Errorf("reused = %v, want [note token]", reused)
	}

	// note omitted entirely, token given a fresh value: only note is reused.
	cfg, reused, err = r.Parse("secret-test", json.RawMessage(`{"url":"https://example.test","token":"fresh"}`), stored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Secrets["note"] != "stored-note" {
		t.Errorf("note = %q, want stored-note", cfg.Secrets["note"])
	}
	if cfg.Secrets["token"] != "fresh" {
		t.Errorf("token = %q, want fresh", cfg.Secrets["token"])
	}
	if len(reused) != 1 || reused[0] != "note" {
		t.Errorf("reused = %v, want [note]", reused)
	}
}

func TestParseUnchangedWithoutStored(t *testing.T) {
	r := newRegistry(t, "secret-test", targets.Server, targets.Never)

	_, _, err := r.Parse("secret-test", json.RawMessage(`{"url":"https://example.test","token":"__unchanged__"}`), map[string]string{})
	if !errors.Is(err, targets.ErrUnchangedWithoutStored) {
		t.Fatalf("Parse error = %v, want ErrUnchangedWithoutStored", err)
	}
	if got := err.Error(); got == "" {
		t.Fatal("Parse error has no message")
	}
}

// TestParseOmittedRequiredSecretFailsInType covers the batch-1 review fix:
// an omitted *required* secret (token) with no stored value is never
// ErrUnchangedWithoutStored — that sentinel is only for an explicit
// __unchanged__ — Registry.Parse instead leaves it absent and the type's
// own Parse rejects the missing required field on its own terms.
func TestParseOmittedRequiredSecretFailsInType(t *testing.T) {
	r := newRegistry(t, "secret-test", targets.Server, targets.Never)

	_, _, err := r.Parse("secret-test", json.RawMessage(`{"url":"https://example.test"}`), map[string]string{})
	if err == nil {
		t.Fatal("Parse did not fail for an omitted required secret with no stored value")
	}
	if errors.Is(err, targets.ErrUnchangedWithoutStored) {
		t.Fatalf("Parse error = %v, want a type-level error, not ErrUnchangedWithoutStored", err)
	}
}

// TestParseOmittedOptionalSecretStaysAbsent covers the batch-1 review fix
// directly: creating a target without its optional secret (note) never
// errors — the field is simply left absent, not reused, and every other
// field parses normally.
func TestParseOmittedOptionalSecretStaysAbsent(t *testing.T) {
	r := newRegistry(t, "secret-test", targets.Server, targets.Never)

	cfg, reused, err := r.Parse("secret-test", json.RawMessage(`{"url":"https://example.test","token":"fresh"}`), map[string]string{})
	if err != nil {
		t.Fatalf("Parse without note: %v", err)
	}
	if _, ok := cfg.Secrets["note"]; ok {
		t.Errorf("note present without ever being set: %v", cfg.Secrets)
	}
	if cfg.Secrets["token"] != "fresh" {
		t.Errorf("token = %q, want fresh", cfg.Secrets["token"])
	}
	if len(reused) != 0 {
		t.Errorf("reused = %v, want none", reused)
	}
}

func TestParseExplicitEmptyClears(t *testing.T) {
	r := newRegistry(t, "secret-test", targets.Server, targets.Never)
	stored := map[string]string{"token": "stored-token", "note": "stored-note"}

	cfg, reused, err := r.Parse("secret-test", json.RawMessage(`{"url":"https://example.test","token":"fresh","note":""}`), stored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := cfg.Secrets["note"]; ok {
		t.Errorf("note still present after explicit clear: %v", cfg.Secrets)
	}
	for _, k := range reused {
		if k == "note" {
			t.Errorf("cleared note reported as reused: %v", reused)
		}
	}
}

func TestParseRequiredSecretClearedFails(t *testing.T) {
	r := newRegistry(t, "secret-test", targets.Server, targets.Never)
	stored := map[string]string{"token": "stored-token"}

	_, _, err := r.Parse("secret-test", json.RawMessage(`{"url":"https://example.test","token":""}`), stored)
	if err == nil {
		t.Fatal("Parse did not fail clearing the required token")
	}
}

func TestResolveSideMatrix(t *testing.T) {
	either := &targetstest.Secret{Code: "either-test", Mode: targets.Either, Policy: targets.Never}
	forced := &targetstest.Secret{Code: "forced-test", Mode: targets.Agent, Policy: targets.Never}

	cases := []struct {
		name      string
		t         targets.Target
		requested string
		want      targets.Mode
		wantErr   bool
	}{
		{"either server", either, "server", targets.Server, false},
		{"either agent", either, "agent", targets.Agent, false},
		{"either empty", either, "", "", true},
		{"either garbage", either, "bogus", "", true},
		{"forced empty", forced, "", targets.Agent, false},
		{"forced matching", forced, "agent", targets.Agent, false},
		{"forced mismatch", forced, "server", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := targets.ResolveSide(c.t, c.requested)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ResolveSide(%q) = %v, nil, want an error", c.requested, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveSide(%q): %v", c.requested, err)
			}
			if got != c.want {
				t.Fatalf("ResolveSide(%q) = %q, want %q", c.requested, got, c.want)
			}
		})
	}
}

func TestNeedsKeyMatrix(t *testing.T) {
	r := targets.NewRegistry()
	r.Register(&targetstest.Secret{Code: "never-test", Mode: targets.Server, Policy: targets.Never})
	r.Register(&targetstest.Secret{Code: "always-test", Mode: targets.Server, Policy: targets.Always})
	r.Register(&targetstest.Secret{Code: "optional-test", Mode: targets.Server, Policy: targets.Optional})

	cases := []struct {
		typ    string
		public string
		want   bool
	}{
		{"never-test", `{}`, false},
		{"always-test", `{}`, true},
		{"optional-test", `{}`, false},
		{"optional-test", `{"includeKey":true}`, true},
		{"optional-test", `{"includeKey":false}`, false},
	}
	for _, c := range cases {
		got, err := r.NeedsKey(c.typ, json.RawMessage(c.public))
		if err != nil {
			t.Fatalf("NeedsKey(%s, %s): %v", c.typ, c.public, err)
		}
		if got != c.want {
			t.Errorf("NeedsKey(%s, %s) = %v, want %v", c.typ, c.public, got, c.want)
		}
	}
}

func TestParseUnknownType(t *testing.T) {
	r := targets.NewRegistry()
	if _, _, err := r.Parse("nope", json.RawMessage(`{}`), map[string]string{}); err == nil {
		t.Fatal("Parse did not fail for an unregistered type")
	}
}
