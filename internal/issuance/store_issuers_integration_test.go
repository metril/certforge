//go:build integration

package issuance

import (
	"context"
	"errors"
	"testing"
)

// TestCATypeRoundTrip covers Phase 5A Task 1: a CA created with no type
// defaults to acme with an empty config and round-trips through GetCA; an
// unknown type is a 422 on the type field; vaultpki (not built until T8) is
// also a 422, "not available yet" — localca's own CRUD matrix is Task 7's
// TestLocalCACRUDMatrix (internal/api/private_ca_integration_test.go).
func TestCATypeRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	ca, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Round", Preset: "custom", DirectoryURL: "https://round.test/dir"})
	if err != nil {
		t.Fatal(err)
	}
	if ca.Type != CATypeACME {
		t.Fatalf("Type = %q, want %q", ca.Type, CATypeACME)
	}
	if len(ca.Config) != 0 {
		t.Fatalf("Config = %v, want empty", ca.Config)
	}

	got, err := f.store.GetCA(ctx, f.org, ca.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != CATypeACME || len(got.Config) != 0 {
		t.Fatalf("GetCA round trip: Type=%q Config=%v", got.Type, got.Config)
	}

	var ve *ValidationError
	_, err = f.store.CreateCA(ctx, f.org, CAInput{Name: "Bogus", Preset: "custom", DirectoryURL: "https://bogus.test/dir", Type: "bogus"})
	if !errors.As(err, &ve) || ve.Field != "type" {
		t.Fatalf("unknown type: err = %v, want a type ValidationError", err)
	}

	_, err = f.store.CreateCA(ctx, f.org, CAInput{Name: "Vault", Type: CATypeVaultPKI})
	if !errors.As(err, &ve) || ve.Field != "type" || ve.Msg != "not available yet" {
		t.Fatalf("vaultpki type: err = %v, want type ValidationError %q", err, "not available yet")
	}
}
