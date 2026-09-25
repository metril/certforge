//go:build integration

package authn

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/settings"
)

// TestSettingsSourceCacheExpiry checks that Get re-reads the store once the
// cache TTL has elapsed (by the source's own clock), and serves the cached
// value before that.
func TestSettingsSourceCacheExpiry(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	key := bytes.Repeat([]byte{7}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	store := settings.NewStore(q, env)
	reg := settings.NewRegistry()
	if err := RegisterSettings(reg); err != nil {
		t.Fatal(err)
	}
	src, err := NewSettingsSource(store, reg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	src.now = func() time.Time { return now }

	st, err := src.Get(ctx)
	if err != nil || st.SessionTTLHours != 12 {
		t.Fatalf("initial get: %+v %v", st, err)
	}

	sec, _ := reg.Section(SettingsSection)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSectionTx(ctx, tx, sec, []byte(`{"sessionTtlHours":48}`)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Still within the TTL: the cached (stale) value is served.
	st, err = src.Get(ctx)
	if err != nil || st.SessionTTLHours != 12 {
		t.Fatalf("within ttl: %+v %v", st, err)
	}

	// Past the TTL: the source re-reads and picks up the new value.
	now = now.Add(31 * time.Second)
	st, err = src.Get(ctx)
	if err != nil || st.SessionTTLHours != 48 {
		t.Fatalf("after ttl: %+v %v", st, err)
	}
}
