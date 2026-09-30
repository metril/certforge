package targetstest_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/targetstest"
)

func TestSecretParseValid(t *testing.T) {
	s := &targetstest.Secret{Code: "secret-test", Mode: targets.Server, Policy: targets.Optional}
	cfg, err := s.Parse(json.RawMessage(`{"url":"https://example.test","token":"tok","includeKey":true}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.URLs) != 1 || cfg.URLs[0] != "https://example.test" {
		t.Errorf("URLs = %v, want [https://example.test]", cfg.URLs)
	}
	if !cfg.NeedsKey {
		t.Error("NeedsKey = false, want true (Optional + includeKey)")
	}
	if cfg.Secrets["token"] != "tok" {
		t.Errorf("Secrets[token] = %q, want tok", cfg.Secrets["token"])
	}
}

func TestSecretParseRejectsMissingURL(t *testing.T) {
	s := &targetstest.Secret{Code: "secret-test", Mode: targets.Server, Policy: targets.Never}
	if _, err := s.Parse(json.RawMessage(`{"token":"tok"}`)); err == nil {
		t.Fatal("Parse did not fail with no url")
	}
}

func TestSecretParseRejectsBadURL(t *testing.T) {
	s := &targetstest.Secret{Code: "secret-test", Mode: targets.Server, Policy: targets.Never}
	if _, err := s.Parse(json.RawMessage(`{"url":"not a uri","token":"tok"}`)); err == nil {
		t.Fatal("Parse did not fail with an invalid uri")
	}
}

func TestSecretParseRejectsMissingToken(t *testing.T) {
	s := &targetstest.Secret{Code: "secret-test", Mode: targets.Server, Policy: targets.Never}
	if _, err := s.Parse(json.RawMessage(`{"url":"https://example.test"}`)); err == nil {
		t.Fatal("Parse did not fail with no token")
	}
}

func TestSecretDeployRecordsAndReturnsErr(t *testing.T) {
	wantErr := errors.New("boom")
	s := &targetstest.Secret{Code: "secret-test", Mode: targets.Server, Policy: targets.Never, Err: wantErr}
	req := targets.Request{GrantID: "g1"}

	_, err := s.Deploy(context.Background(), req)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Deploy error = %v, want %v", err, wantErr)
	}
	if len(s.Calls) != 1 || s.Calls[0].GrantID != "g1" {
		t.Fatalf("Calls = %v, want one call with GrantID g1", s.Calls)
	}

	s.Err = nil
	if _, err := s.Deploy(context.Background(), req); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(s.Calls) != 2 {
		t.Fatalf("Calls = %v, want 2 recorded calls", s.Calls)
	}
}
