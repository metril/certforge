//go:build integration

package metrics_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/metrics"
	"github.com/metril/certforge/internal/settings"
)

// TestPrometheusUnchangedTokenPassesPutSectionTx is the full-pipeline
// version of batch-1 review finding 2: PutSectionTx runs Section.Validate
// (the schema) before Section.ValidateUpdate (checkTokenRequired), exactly
// like the "prometheus" settings PUT handler does — a schema-level
// minLength on bearerToken would 422 the ordinary "keep the stored token"
// update on the __unchanged__ sentinel's own length, never reaching
// ValidateUpdate at all.
func TestPrometheusUnchangedTokenPassesPutSectionTx(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)

	key := bytes.Repeat([]byte{7}, 32)
	wrapper := crypto.NewStaticWrapper(crypto.KeyID(key), key)
	env := crypto.NewEnvelope(wrapper)
	store := settings.NewStore(q, env)

	reg := settings.NewRegistry()
	if err := metrics.RegisterSettings(reg); err != nil {
		t.Fatal(err)
	}
	sec, ok := reg.Section(metrics.SectionName)
	if !ok {
		t.Fatal("prometheus section not registered")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := store.PutSectionTx(ctx, tx, sec, []byte(`{"enabled":true,"bearerToken":"0123456789abcdef"}`)); err != nil {
		t.Fatalf("first save with a fresh 16-character token: %v", err)
	}
	if _, err := store.PutSectionTx(ctx, tx, sec, []byte(`{"enabled":true,"bearerToken":"__unchanged__"}`)); err != nil {
		t.Fatalf("re-save with __unchanged__: %v", err)
	}
}
