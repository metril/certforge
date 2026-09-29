//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
)

// notifyFixture is Task 6's own apiFixture: a Server whose Deps.Notify is a
// real notify.Service (against a live Postgres, a real Box and every
// notifier type registered exactly as cmd/certforge/serve.go wires them),
// separate from issuance_fixture_integration_test.go's apiFixture since
// that one has no Notify (and building a full issuance/agents/deploy stack
// for channel and event tests would only add unused setup).
type notifyFixture struct {
	srv      *Server
	pool     *pgxpool.Pool
	q        *sqlcgen.Queries
	box      crypto.Box
	org      uuid.UUID
	settings *settings.Store
	sections *settings.Registry
}

func newNotifyFixture(t *testing.T) *notifyFixture {
	t.Helper()
	pool, q := dbtest.New(t)
	box := cryptotest.PrefixBox{}
	key := bytes.Repeat([]byte{9}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	settingsStore := settings.NewStore(q, env)
	sections := settings.DefaultRegistry()
	if err := notify.RegisterSettings(sections); err != nil {
		t.Fatal(err)
	}

	settingsFn := func(ctx context.Context) (notify.Settings, error) { return notify.Current(ctx, settingsStore) }
	reg := notify.NewRegistry()
	reg.Register(notify.Webhook{Settings: settingsFn})
	reg.Register(notify.Discord{Settings: settingsFn})
	reg.Register(notify.Ntfy{Settings: settingsFn})
	reg.Register(notify.HomeAssistant{Settings: settingsFn})
	reg.Register(notify.SMTP{Settings: func(ctx context.Context) (notify.SMTPSettings, string, error) {
		return notify.CurrentSMTP(ctx, settingsStore, sections)
	}})

	aud := audit.New(pool, bytes.Repeat([]byte{6}, 32))
	svc := &notify.Service{Store: &notify.Store{Pool: pool, Q: q}, Registry: reg, Box: box, Settings: settingsStore,
		Audit: aud, Log: slog.Default()}
	srv := &Server{d: Deps{Log: slog.Default(), Pool: pool, Queries: q, Auditor: aud, Notify: svc,
		Settings: settingsStore, Sections: sections, Box: box}}
	return &notifyFixture{srv: srv, pool: pool, q: q, box: box, org: dbtest.Org(t, pool), settings: settingsStore, sections: sections}
}

// as returns a context for a user holding role in the fixture org; admin is
// bound globally (same pattern as issuance_fixture_integration_test.go's
// apiFixture.as).
func (f *notifyFixture) as(role string) context.Context {
	b := authn.Binding{Role: role, OrgID: &f.org}
	if role == authz.RoleAdmin {
		b.OrgID = nil
	}
	return authn.WithPrincipal(context.Background(), authn.Principal{Kind: authn.KindUser, UserID: uuid.New(),
		Roles: []string{role}, Bindings: []authn.Binding{b}, OrgIDs: []uuid.UUID{f.org}})
}

// allowLoopback flips the "notifications" section's allowLoopbackUrls on,
// so a test channel can target an httptest server (127.0.0.1) without the
// SSRF policy rejecting it at create/update or send time.
func (f *notifyFixture) allowLoopback(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	sec, ok := f.sections.Section(notify.SectionName)
	if !ok {
		t.Fatal("notifications section not registered")
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := f.settings.PutSectionTx(ctx, tx, sec, json.RawMessage(`{"allowLoopbackUrls":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (f *notifyFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// lastAuditDetails returns the most recent details JSON (as text) for
// action against resourceID (same query issuance_fixture_integration_test.go's
// apiFixture.lastAuditDetails runs).
func (f *notifyFixture) lastAuditDetails(t *testing.T, action, resourceID string) string {
	t.Helper()
	var details string
	err := f.pool.QueryRow(context.Background(),
		`SELECT details::text FROM audit_events WHERE action = $1 AND resource_id = $2 ORDER BY id DESC LIMIT 1`, action, resourceID).Scan(&details)
	if err != nil {
		t.Fatal(err)
	}
	return details
}
