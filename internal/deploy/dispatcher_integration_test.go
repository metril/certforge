//go:build integration

package deploy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/targetstest"
)

// dispatcherFixture is a minimal, direct-SQL fixture for Dispatcher.Deploy:
// it never goes through internal/api, only raw inserts for the
// certificate/version/target/grant a deploy needs plus a *targets.Registry
// the test registers its own targetstest.Secret types into (same pattern
// as agents.syncFixture, internal/agents/sync_integration_test.go).
type dispatcherFixture struct {
	pool  *pgxpool.Pool
	q     *sqlcgen.Queries
	certs *certstore.Store
	box   crypto.Box
	reg   *targets.Registry
	disp  *Dispatcher
	org   uuid.UUID
}

func newDispatcherFixture(t *testing.T) *dispatcherFixture {
	t.Helper()
	pool, q := dbtest.New(t)
	box := cryptotest.PrefixBox{}
	certs := certstore.New(pool, box)
	reg := targets.NewRegistry()
	disp := &Dispatcher{
		Pool: pool, Q: q, Reg: reg, Certs: certs, Box: box,
		HTTP: func(context.Context) targets.HTTPFactory { return targets.HTTPFactory{AllowLoopback: true} },
	}
	return &dispatcherFixture{pool: pool, q: q, certs: certs, box: box, reg: reg, disp: disp, org: dbtest.Org(t, pool)}
}

// cert inserts a certificate row with no version and no current_version_id
// (Dispatcher.Deploy never reads current_version_id: the version to deploy
// is the caller's own versionID argument).
func (f *dispatcherFixture) cert(t *testing.T, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO certificates (org_id, name, common_name) VALUES ($1, $2, $3) RETURNING id`,
		f.org, name, name+".example.test").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// version inserts a version of certID; LeafDER/ChainDER/the key are opaque
// bytes (render.PEM.Render and agentproto.CertFingerprint never parse
// them), keyed so a test can tell one version's rendered files apart from
// another's.
func (f *dispatcherFixture) version(t *testing.T, certID uuid.UUID, serial string, withKey bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	iss := &signer.Issued{
		LeafDER: []byte("leaf-" + serial), ChainDER: [][]byte{[]byte("chain-" + serial)},
		NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour), Serial: serial,
	}
	if withKey {
		iss.PrivateKeyPKCS8 = []byte("key-" + serial)
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

// target registers a *targetstest.Secret (mode/policy given) as code and
// stores a deploy target row for it: full is the canonical config (public
// fields plus secret fields, e.g. url/token/note/includeKey) — the same
// shape internal/api's validTarget would split and seal before writing.
// Dispatcher.Deploy never reads deploy_targets.runs_on itself (only the
// registry's own Target.RunsOn, checked against mode), so the stored
// column is set from mode purely for a realistic row.
func (f *dispatcherFixture) target(t *testing.T, code string, mode targets.Mode, policy targets.KeyPolicy, full map[string]any) (uuid.UUID, *targetstest.Secret) {
	t.Helper()
	sec := &targetstest.Secret{Code: code, Mode: mode, Policy: policy}
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
		OrgID: f.org, Name: code, Type: code, RunsOn: string(mode), Config: pub, SecretCfg: sealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dt.ID, sec
}

// grant creates a client-less (server) grant of certID on targetID, with no
// layout (output_spec_id nil): Dispatcher.renderFiles then falls back to
// the four canonical PEM parts.
func (f *dispatcherFixture) grant(t *testing.T, certID, targetID uuid.UUID) uuid.UUID {
	t.Helper()
	g, err := f.q.CreateServerGrant(context.Background(), sqlcgen.CreateServerGrantParams{CertID: certID, DeployTargetID: &targetID})
	if err != nil {
		t.Fatal(err)
	}
	return g.ID
}

// pending upserts grantID's server_deployments row pending on versionID —
// Dispatcher.Deploy is a no-op unless this matches the versionID it is
// called with (the stale-job guard).
func (f *dispatcherFixture) pending(t *testing.T, grantID, versionID uuid.UUID) {
	t.Helper()
	if err := f.q.UpsertServerDeploymentPending(context.Background(), sqlcgen.UpsertServerDeploymentPendingParams{GrantID: grantID, VersionID: &versionID}); err != nil {
		t.Fatal(err)
	}
}

// status returns a grant's server_deployments.status.
func (f *dispatcherFixture) status(t *testing.T, grantID uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.pool.QueryRow(context.Background(), `SELECT status FROM server_deployments WHERE grant_id = $1`, grantID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// lastError returns a grant's server_deployments.last_error.
func (f *dispatcherFixture) lastError(t *testing.T, grantID uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.pool.QueryRow(context.Background(), `SELECT last_error FROM server_deployments WHERE grant_id = $1`, grantID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestServerDeployAnyType covers the registry-driven dispatch itself: a
// test type that is neither vault-kv nor traefik deploys through
// Dispatcher.Deploy, its Request carries the merged (public + decrypted
// secret) config and a non-empty GrantID, and the grant ends up deployed.
func TestServerDeployAnyType(t *testing.T) {
	f := newDispatcherFixture(t)
	certID := f.cert(t, "any-type")
	versionID := f.version(t, certID, "1", false)
	targetID, sec := f.target(t, "any-type-target", targets.Server, targets.Never,
		map[string]any{"url": "https://example.test/hook", "token": "tok-abc123"})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, versionID)

	if err := f.disp.Deploy(context.Background(), grantID, versionID); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(sec.Calls) != 1 {
		t.Fatalf("target.Deploy called %d times, want 1", len(sec.Calls))
	}
	req := sec.Calls[0]
	if req.GrantID == "" {
		t.Error("Request.GrantID is empty")
	}
	if req.GrantID != grantID.String() {
		t.Errorf("Request.GrantID = %q, want %q", req.GrantID, grantID.String())
	}
	var cfg map[string]any
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["token"] != "tok-abc123" {
		t.Errorf("Request.Config = %s, want the merged token", req.Config)
	}
	if req.Side != targets.Server {
		t.Errorf("Request.Side = %q, want server", req.Side)
	}
	if got := f.status(t, grantID); got != "deployed" {
		t.Errorf("status = %q, want deployed", got)
	}
}

// TestServerDeployNoKeyUnlessNeeded covers NeedsKey-gated material: a
// target whose config does not ask for the key never sees a key-bearing
// file, even though the version being deployed has one stored; a target
// that does ask for it (KeyPolicy Optional, includeKey true) gets it.
func TestServerDeployNoKeyUnlessNeeded(t *testing.T) {
	f := newDispatcherFixture(t)
	certID := f.cert(t, "key-gate")
	versionID := f.version(t, certID, "1", true)

	noKeyTarget, noKeySec := f.target(t, "no-key-target", targets.Server, targets.Optional,
		map[string]any{"url": "https://example.test/a", "token": "tok-a", "includeKey": false})
	noKeyGrant := f.grant(t, certID, noKeyTarget)
	f.pending(t, noKeyGrant, versionID)
	if err := f.disp.Deploy(context.Background(), noKeyGrant, versionID); err != nil {
		t.Fatalf("Deploy (no key): %v", err)
	}
	if len(noKeySec.Calls) != 1 {
		t.Fatalf("no-key target.Deploy called %d times, want 1", len(noKeySec.Calls))
	}
	for _, fl := range noKeySec.Calls[0].Files {
		if fl.Secret {
			t.Errorf("no-key deploy carried a secret file %q", fl.Name)
		}
	}

	keyTarget, keySec := f.target(t, "key-target", targets.Server, targets.Optional,
		map[string]any{"url": "https://example.test/b", "token": "tok-b", "includeKey": true})
	keyGrant := f.grant(t, certID, keyTarget)
	f.pending(t, keyGrant, versionID)
	if err := f.disp.Deploy(context.Background(), keyGrant, versionID); err != nil {
		t.Fatalf("Deploy (key): %v", err)
	}
	if len(keySec.Calls) != 1 {
		t.Fatalf("key target.Deploy called %d times, want 1", len(keySec.Calls))
	}
	var sawKey bool
	for _, fl := range keySec.Calls[0].Files {
		if fl.Secret {
			sawKey = true
		}
	}
	if !sawKey {
		t.Error("includeKey deploy carried no secret file")
	}
}

// TestServerDeployLastErrorRedacted covers targets.Redact applied before
// any server_deployments.last_error write: a Deploy failure whose message
// embeds the target's own secret — raw, URL-escaped and base64-encoded —
// must never leave any of those three forms in the stored last_error.
func TestServerDeployLastErrorRedacted(t *testing.T) {
	f := newDispatcherFixture(t)
	certID := f.cert(t, "redact")
	versionID := f.version(t, certID, "1", false)
	token := "a secret/value"
	targetID, sec := f.target(t, "redact-target", targets.Server, targets.Never,
		map[string]any{"url": "https://example.test/hook", "token": token})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, versionID)

	b64 := base64.StdEncoding.EncodeToString([]byte(token))
	sec.Err = fmt.Errorf("upstream rejected: raw=%s escaped=%s b64=%s", token, url.QueryEscape(token), b64)

	err := f.disp.Deploy(context.Background(), grantID, versionID)
	if err == nil {
		t.Fatal("Deploy = nil, want the target's own error")
	}
	// batch 2 review, finding 1: river logs and stores whatever error Deploy
	// returns (jobexecutor's "Job errored" log, river_job.errors), so the
	// returned error itself — not just the stored last_error — must be
	// redacted, never the raw cause.
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), url.QueryEscape(token)) || strings.Contains(err.Error(), b64) {
		t.Errorf("Deploy's returned error contains the secret: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("Deploy's returned error has no [redacted] marker: %q", err.Error())
	}
	got := f.lastError(t, grantID)
	if strings.Contains(got, token) {
		t.Errorf("last_error contains the raw secret: %q", got)
	}
	if strings.Contains(got, url.QueryEscape(token)) {
		t.Errorf("last_error contains the escaped secret: %q", got)
	}
	if strings.Contains(got, b64) {
		t.Errorf("last_error contains the base64 secret: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("last_error has no [redacted] marker: %q", got)
	}
	if got := f.status(t, grantID); got != "failed" {
		t.Errorf("status = %q, want failed", got)
	}
}

// TestServerDeploySuccessClearsLastError covers MarkServerDeploymentDeployed:
// a failed attempt's last_error does not linger once a later attempt at the
// same version succeeds.
func TestServerDeploySuccessClearsLastError(t *testing.T) {
	f := newDispatcherFixture(t)
	certID := f.cert(t, "clears")
	versionID := f.version(t, certID, "1", false)
	targetID, sec := f.target(t, "clears-target", targets.Server, targets.Never,
		map[string]any{"url": "https://example.test/hook", "token": "tok-clears"})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, versionID)

	sec.Err = fmt.Errorf("boom")
	if err := f.disp.Deploy(context.Background(), grantID, versionID); err == nil {
		t.Fatal("Deploy = nil, want an error on the first attempt")
	}
	if f.lastError(t, grantID) == "" {
		t.Fatal("last_error is empty after a failed attempt")
	}

	sec.Err = nil
	f.pending(t, grantID, versionID) // same version: re-arms the stale-job guard
	if err := f.disp.Deploy(context.Background(), grantID, versionID); err != nil {
		t.Fatalf("Deploy (retry): %v", err)
	}
	if got := f.lastError(t, grantID); got != "" {
		t.Errorf("last_error = %q after a successful deploy, want empty", got)
	}
	if got := f.status(t, grantID); got != "deployed" {
		t.Errorf("status = %q, want deployed", got)
	}
}

// TestServerDeployRejectsAgentType covers Dispatcher.Deploy's own defense
// in depth against a client-less grant somehow pointed at an agent-run
// type (the API never allows creating one this way; this fixture writes
// the deploy_targets row directly, bypassing that check): Deploy fails
// without ever calling the target's own Deploy.
func TestServerDeployRejectsAgentType(t *testing.T) {
	f := newDispatcherFixture(t)
	certID := f.cert(t, "agent-type")
	versionID := f.version(t, certID, "1", false)
	targetID, sec := f.target(t, "agent-only-target", targets.Agent, targets.Never,
		map[string]any{"url": "https://example.test/hook", "token": "tok-agent"})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, versionID)

	if err := f.disp.Deploy(context.Background(), grantID, versionID); err == nil {
		t.Fatal("Deploy = nil, want an error for an agent-run type")
	}
	if len(sec.Calls) != 0 {
		t.Fatalf("target.Deploy was called %d times, want 0", len(sec.Calls))
	}
	if got := f.status(t, grantID); got != "failed" {
		t.Errorf("status = %q, want failed", got)
	}
}
