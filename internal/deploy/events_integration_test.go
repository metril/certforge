//go:build integration

// package deploy_test, not deploy: this test wires internal/notify's real
// DeployEvents/Emitter/Sources into a Dispatcher, and internal/notify
// imports internal/deploy — an internal test file (same package as
// internal/deploy) importing a package that imports internal/deploy back
// is a real cycle in the "deploy [deploy.test]" build variant ("go vet
// -tags integration" flags it as such); only an external test package
// avoids that, at the cost of re-declaring the small fixture
// dispatcher_integration_test.go's own dispatcherFixture already has
// (unexported, so it cannot be reused across the package boundary).
package deploy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/targetstest"
)

// fakeNotifyInserter is notify.Inserter backed by memory (same pattern as
// notify's own fakeInserter, internal/notify/helpers_integration_test.go):
// the emitted event/delivery rows land in real Postgres; only the
// certforge_notify_deliver job insert itself needs to be observed here.
type fakeNotifyInserter struct{}

func (fakeNotifyInserter) InsertTx(context.Context, pgx.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}}, nil
}

// eventsFixture is dispatcher_integration_test.go's own dispatcherFixture,
// minus the parts these tests don't need, plus a real *notify.Emitter/
// Sources wired to the dispatcher's Events field.
type eventsFixture struct {
	pool    *pgxpool.Pool
	q       *sqlcgen.Queries
	certs   *certstore.Store
	box     crypto.Box
	reg     *targets.Registry
	disp    *deploy.Dispatcher
	sources *notify.Sources
	org     uuid.UUID
}

func newEventsFixture(t *testing.T) *eventsFixture {
	t.Helper()
	pool, q := dbtest.New(t)
	box := cryptotest.PrefixBox{}
	certs := certstore.New(pool, box)
	reg := targets.NewRegistry()
	emitter := &notify.Emitter{Pool: pool, River: fakeNotifyInserter{}}
	disp := &deploy.Dispatcher{
		Pool: pool, Q: q, Reg: reg, Certs: certs, Box: box,
		HTTP:   func(context.Context) targets.HTTPFactory { return targets.HTTPFactory{AllowLoopback: true} },
		Events: notify.DeployEvents{E: emitter},
	}
	key := bytes.Repeat([]byte{7}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	store := settings.NewStore(q, env)
	sources := &notify.Sources{Q: q, Emitter: emitter, Settings: store}
	return &eventsFixture{pool: pool, q: q, certs: certs, box: box, reg: reg, disp: disp, sources: sources, org: dbtest.Org(t, pool)}
}

func (f *eventsFixture) cert(t *testing.T, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO certificates (org_id, name, common_name) VALUES ($1, $2, $3) RETURNING id`,
		f.org, name, name+".example.test").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *eventsFixture) version(t *testing.T, certID uuid.UUID, serial string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	iss := &signer.Issued{
		LeafDER: []byte("leaf-" + serial), ChainDER: [][]byte{[]byte("chain-" + serial)},
		NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour), Serial: serial,
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	v, err := f.certs.Insert(ctx, tx, certID, iss, "ec256", certstore.InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return v.ID
}

func (f *eventsFixture) target(t *testing.T, code string, full map[string]any) (uuid.UUID, *targetstest.Secret) {
	t.Helper()
	sec := &targetstest.Secret{Code: code, Mode: targets.Server, Policy: targets.Never}
	f.reg.Register(sec)
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	pub, secrets, err := targets.Split(sec.Schema(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if len(secrets) > 0 {
		sb, err := json.Marshal(secrets)
		if err != nil {
			t.Fatal(err)
		}
		if sealed, err = f.box.Seal(context.Background(), sb); err != nil {
			t.Fatal(err)
		}
	}
	dt, err := f.q.CreateDeployTarget(context.Background(), sqlcgen.CreateDeployTargetParams{
		OrgID: f.org, Name: code, Type: code, RunsOn: string(targets.Server), Config: pub, SecretCfg: sealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dt.ID, sec
}

func (f *eventsFixture) grant(t *testing.T, certID, targetID uuid.UUID) uuid.UUID {
	t.Helper()
	g, err := f.q.CreateServerGrant(context.Background(), sqlcgen.CreateServerGrantParams{CertID: certID, DeployTargetID: &targetID})
	if err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func (f *eventsFixture) pending(t *testing.T, grantID, versionID uuid.UUID) {
	t.Helper()
	if err := f.q.UpsertServerDeploymentPending(context.Background(), sqlcgen.UpsertServerDeploymentPendingParams{GrantID: grantID, VersionID: &versionID}); err != nil {
		t.Fatal(err)
	}
}

func (f *eventsFixture) lastError(t *testing.T, grantID uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.pool.QueryRow(context.Background(), `SELECT last_error FROM server_deployments WHERE grant_id = $1`, grantID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// eventCount returns how many notification_events rows exist for kind.
func eventCount(t *testing.T, pool *pgxpool.Pool, kind string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM notification_events WHERE kind = $1`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// eventDetails returns the raw details jsonb (as a string) for the sole
// event with the given dedupe_key.
func eventDetails(t *testing.T, pool *pgxpool.Pool, dedupeKey string) string {
	t.Helper()
	var d []byte
	if err := pool.QueryRow(context.Background(), `SELECT details::text FROM notification_events WHERE dedupe_key = $1`, dedupeKey).Scan(&d); err != nil {
		t.Fatal(err)
	}
	return string(d)
}

// TestDispatcherEmitsDeployFailedOnce covers the task-7 brief's core
// contract: two failing attempts at the same (grant, version) give one
// notification_events row (the immediate emit fires on the first attempt;
// the second's DedupeKey collision is a silent no-op), and a later
// certforge_notify_scan run — the hourly ScanFailedServerDeployments
// backstop — adds none, because it shares the exact same DedupeKey.
func TestDispatcherEmitsDeployFailedOnce(t *testing.T) {
	f := newEventsFixture(t)
	ctx := context.Background()
	certID := f.cert(t, "emits-once")
	versionID := f.version(t, certID, "1")
	targetID, sec := f.target(t, "emits-once-target", map[string]any{"url": "https://example.test/hook", "token": "tok-once"})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, versionID)

	sec.Err = fmt.Errorf("boom")
	if err := f.disp.Deploy(ctx, grantID, versionID); err == nil {
		t.Fatal("Deploy (attempt 1) = nil, want an error")
	}
	if got := eventCount(t, f.pool, "deploy.failed"); got != 1 {
		t.Fatalf("events after attempt 1 = %d, want 1", got)
	}

	f.pending(t, grantID, versionID) // re-arms the stale-job guard
	if err := f.disp.Deploy(ctx, grantID, versionID); err == nil {
		t.Fatal("Deploy (attempt 2) = nil, want an error")
	}
	if got := eventCount(t, f.pool, "deploy.failed"); got != 1 {
		t.Fatalf("events after attempt 2 = %d, want 1 (deduped)", got)
	}

	if err := f.sources.Scan(ctx); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := eventCount(t, f.pool, "deploy.failed"); got != 1 {
		t.Fatalf("events after scan = %d, want 1 (scan's own dedupe key matches the immediate emit's)", got)
	}
}

// TestDeployFailedPayloadRedacted covers R10: the notification_events row
// the immediate emit writes carries the same redacted last_error
// Dispatcher.fail records on server_deployments, never the raw secret.
func TestDeployFailedPayloadRedacted(t *testing.T) {
	f := newEventsFixture(t)
	ctx := context.Background()
	certID := f.cert(t, "payload-redacted")
	versionID := f.version(t, certID, "1")
	token := "a secret/value"
	targetID, sec := f.target(t, "payload-redacted-target", map[string]any{"url": "https://example.test/hook", "token": token})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, versionID)

	sec.Err = fmt.Errorf("upstream rejected token=%s", token)
	if err := f.disp.Deploy(ctx, grantID, versionID); err == nil {
		t.Fatal("Deploy = nil, want an error")
	}

	dedupeKey := fmt.Sprintf("deploy.failed:%s:%s", grantID, versionID)
	details := eventDetails(t, f.pool, dedupeKey)
	if strings.Contains(details, token) {
		t.Errorf("event details contain the raw secret: %s", details)
	}
	if !strings.Contains(details, "[redacted]") {
		t.Errorf("event details have no [redacted] marker: %s", details)
	}
	if !strings.Contains(details, "payload-redacted-target") {
		t.Errorf("event details missing target name: %s", details)
	}
	wantLastError := f.lastError(t, grantID)
	if !strings.Contains(details, wantLastError) {
		t.Errorf("event details lastError does not match server_deployments.last_error %q: %s", wantLastError, details)
	}
}

// TestDeployFailedPayloadRedactsURL covers the review fix: the immediate
// deploy.failed emit (DeployEvents.DeployFailed) must strip an embedded
// Vault/target transport URL the same way scan.go's own backstop scan
// does (redactURLs), not just the secret value. Before the fix, the
// immediate emit stored f.LastError verbatim and, because it fires first
// and wins the shared dedupe key, the scan's URL-scrubbed payload never
// lands.
func TestDeployFailedPayloadRedactsURL(t *testing.T) {
	f := newEventsFixture(t)
	ctx := context.Background()
	certID := f.cert(t, "payload-redacts-url")
	versionID := f.version(t, certID, "1")
	targetID, sec := f.target(t, "payload-redacts-url-target", map[string]any{"url": "https://example.test/hook", "token": "tok-url"})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, versionID)

	leakedURL := "https://vault.internal.example:8200/v1/secret/data/x"
	sec.Err = fmt.Errorf(`Put "%s": dial tcp 10.0.0.5:8200: connect: connection refused`, leakedURL)
	if err := f.disp.Deploy(ctx, grantID, versionID); err == nil {
		t.Fatal("Deploy = nil, want an error")
	}

	dedupeKey := fmt.Sprintf("deploy.failed:%s:%s", grantID, versionID)
	details := eventDetails(t, f.pool, dedupeKey)
	if strings.Contains(details, leakedURL) {
		t.Errorf("event details contain the raw URL: %s", details)
	}
	if strings.Contains(details, "10.0.0.5") {
		t.Errorf("event details contain the raw dial address: %s", details)
	}
	if !strings.Contains(details, "<redacted-url>") {
		t.Errorf("event details have no <redacted-url> marker: %s", details)
	}
}

// TestNewVersionEmitsAgain covers the DedupeKey's own versionID component:
// a fresh certificate version failing again on the same grant is a new
// condition (a different DedupeKey), so it emits its own event rather than
// deduping against the first version's.
func TestNewVersionEmitsAgain(t *testing.T) {
	f := newEventsFixture(t)
	ctx := context.Background()
	certID := f.cert(t, "new-version")
	v1 := f.version(t, certID, "1")
	targetID, sec := f.target(t, "new-version-target", map[string]any{"url": "https://example.test/hook", "token": "tok-nv"})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, v1)

	sec.Err = fmt.Errorf("boom")
	if err := f.disp.Deploy(ctx, grantID, v1); err == nil {
		t.Fatal("Deploy (v1) = nil, want an error")
	}
	if got := eventCount(t, f.pool, "deploy.failed"); got != 1 {
		t.Fatalf("events after v1 = %d, want 1", got)
	}

	v2 := f.version(t, certID, "2")
	f.pending(t, grantID, v2)
	if err := f.disp.Deploy(ctx, grantID, v2); err == nil {
		t.Fatal("Deploy (v2) = nil, want an error")
	}
	if got := eventCount(t, f.pool, "deploy.failed"); got != 2 {
		t.Fatalf("events after v2 = %d, want 2 (a new version is a new condition)", got)
	}
}
