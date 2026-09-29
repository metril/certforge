//go:build integration

package notify_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify"
)

// TestExpiryScanOncePerVersion: two scans of the same expiring version emit
// exactly one cert.expiring event; a new version (a fresh renewal) brings a
// new one.
func TestExpiryScanOncePerVersion(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})
	setNotifySettings(t, pool, 0, 7)

	certID := insertCert(t, pool, org, "example", "example.test", nil)
	v1 := insertVersion(t, pool, certID, time.Now().Add(3*24*time.Hour), uuid.Nil)
	setCurrentVersion(t, pool, certID, v1)

	s := newSources(pool, &fakeInserter{})

	if err := s.Scan(ctx); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	if got := eventCount(t, pool, "cert.expiring"); got != 1 {
		t.Fatalf("events after scan 1 = %d, want 1", got)
	}

	if err := s.Scan(ctx); err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if got := eventCount(t, pool, "cert.expiring"); got != 1 {
		t.Fatalf("events after scan 2 = %d, want still 1", got)
	}

	// A new version (renewal) is a new condition.
	v2 := insertVersion(t, pool, certID, time.Now().Add(3*24*time.Hour), uuid.Nil)
	setCurrentVersion(t, pool, certID, v2)
	if err := s.Scan(ctx); err != nil {
		t.Fatalf("scan 3: %v", err)
	}
	if got := eventCount(t, pool, "cert.expiring"); got != 2 {
		t.Fatalf("events after new version = %d, want 2", got)
	}
}

// cert.expiring must not fire for a version outside the warning window, or
// for a certificate's old (non-current) version.
func TestExpiryScanOnlyCurrentVersionWithinWindow(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})
	setNotifySettings(t, pool, 0, 7)

	certID := insertCert(t, pool, org, "far", "far.example.test", nil)
	far := insertVersion(t, pool, certID, time.Now().Add(60*24*time.Hour), uuid.Nil)
	setCurrentVersion(t, pool, certID, far)

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "cert.expiring"); got != 0 {
		t.Fatalf("events = %d, want 0 (outside the warning window)", got)
	}
}

func TestExpiredScan(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	certID := insertCert(t, pool, org, "example", "example.test", nil)
	v1 := insertVersion(t, pool, certID, time.Now().Add(-24*time.Hour), uuid.Nil)
	setCurrentVersion(t, pool, certID, v1)

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "cert.expired"); got != 1 {
		t.Fatalf("events after scan 1 = %d, want 1", got)
	}
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "cert.expired"); got != 1 {
		t.Fatalf("events after scan 2 = %d, want still 1", got)
	}
}

// TestExpiredScanRespectsRetentionWindow: batch-3 review finding 2 — once
// a condition's own dedupe row has aged out of notification_events (the
// hourly prune deletes anything older than EventRetention), the scan must
// not treat the still-ongoing condition as new again. Deleting the dedupe
// row directly stands in for the passage of time the real prune needs;
// moving Sources' own clock far enough forward that the version's fixed
// not_after now also predates the retention window is what actually
// exercises ScanExpiredCertificateVersions' own since bound — without it,
// NOT EXISTS alone (dedupe row gone) would let this re-emit.
func TestExpiredScanRespectsRetentionWindow(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	certID := insertCert(t, pool, org, "ancient", "ancient.example.test", nil)
	v1 := insertVersion(t, pool, certID, time.Now().Add(-24*time.Hour), uuid.Nil)
	setCurrentVersion(t, pool, certID, v1)

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "cert.expired"); got != 1 {
		t.Fatalf("events after scan 1 = %d, want 1", got)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM notification_events WHERE dedupe_key = $1`, "cert.expired:"+v1.String()); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(notify.EventRetention + 24*time.Hour)
	s.Now = func() time.Time { return future }

	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "cert.expired"); got != 0 {
		t.Fatalf("events after prune + retention window = %d, want 0 (must not re-emit)", got)
	}
}

// TestServerDeployFailedRedactsHost: batch-3 review finding 3 — a
// server-run deployment's stored last_error can be a raw Vault transport
// error embedding the Vault address (a *url.Error's own Error() text,
// which vault.Redact never strips — it only scrubs a token/secretId it
// still holds, not the address). The resulting deploy.failed event's
// details must never carry that host or the underlying dial address (R10).
func TestServerDeployFailedRedactsHost(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	serverTarget := insertDeployTarget(t, pool, org, "server-target", "server")
	serverCert := insertCert(t, pool, org, "server-cert", "server.example.test", nil)
	serverVersion := insertVersion(t, pool, serverCert, time.Now().Add(90*24*time.Hour), uuid.Nil)
	const host = "vault.internal.example.net"
	vaultErr := `vault: request PUT "https://` + host + `:8200/v1/secret/data/certs/server-cert": dial tcp 10.0.5.7:8200: connect: connection refused`
	grantID := insertServerGrant(t, pool, serverCert, serverTarget, "failed", serverVersion, vaultErr)

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "deploy.failed"); got != 1 {
		t.Fatalf("deploy.failed events = %d, want 1", got)
	}
	details := eventDetails(t, pool, fmt.Sprintf("deploy.failed:%s:%s", grantID, serverVersion))
	if strings.Contains(details, host) {
		t.Errorf("deploy.failed details leaked the Vault host: %s", details)
	}
	if strings.Contains(details, "10.0.5.7") {
		t.Errorf("deploy.failed details leaked the dial address: %s", details)
	}
}

// TestDeployFailedAndDriftOnce covers all three deployment failure shapes:
// an agent-run grant in state failed, one in state drift, and a
// server-run grant whose server_deployments.status is failed — each
// emits exactly once across two scans.
func TestDeployFailedAndDriftOnce(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	client := insertClient(t, pool, org, "client-1", clientOpts{})
	agentTarget := insertDeployTarget(t, pool, org, "agent-target", "agent")
	failedCert := insertCert(t, pool, org, "failed-cert", "failed.example.test", nil)
	failedVersion := insertVersion(t, pool, failedCert, time.Now().Add(90*24*time.Hour), uuid.Nil)
	insertAgentGrant(t, pool, client, failedCert, agentTarget, "failed", failedVersion, "deploy failed: disk full")

	driftCert := insertCert(t, pool, org, "drift-cert", "drift.example.test", nil)
	driftVersion := insertVersion(t, pool, driftCert, time.Now().Add(90*24*time.Hour), uuid.Nil)
	insertAgentGrant(t, pool, client, driftCert, agentTarget, "drift", driftVersion, "")

	serverTarget := insertDeployTarget(t, pool, org, "server-target", "server")
	serverCert := insertCert(t, pool, org, "server-cert", "server.example.test", nil)
	serverVersion := insertVersion(t, pool, serverCert, time.Now().Add(90*24*time.Hour), uuid.Nil)
	insertServerGrant(t, pool, serverCert, serverTarget, "failed", serverVersion, "vault write failed")

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "deploy.failed"); got != 2 {
		t.Fatalf("deploy.failed events = %d, want 2 (agent + server)", got)
	}
	if got := eventCount(t, pool, "deploy.drift"); got != 1 {
		t.Fatalf("deploy.drift events = %d, want 1", got)
	}

	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "deploy.failed"); got != 2 {
		t.Fatalf("deploy.failed events after scan 2 = %d, want still 2", got)
	}
	if got := eventCount(t, pool, "deploy.drift"); got != 1 {
		t.Fatalf("deploy.drift events after scan 2 = %d, want still 1", got)
	}
}

// TestDeployDriftDoesNotReemitAfterPrune (final review fix wave, finding
// 1): a drift that lasts past the prune window emits once, never a second
// time just because its dedupe row aged out. deployments.updated_at moves
// on every agent report regardless of whether state changed (simulated
// here directly, since the real column uses Postgres' own now(), not
// Sources' overridable clock) — bounding the scan on that column would
// keep a persistently-drifted grant "recent" forever, re-emitting once its
// dedupe row is pruned. state_changed_at, which only moves on an actual
// transition, must age it out instead.
func TestDeployDriftDoesNotReemitAfterPrune(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	client := insertClient(t, pool, org, "client-1", clientOpts{})
	target := insertDeployTarget(t, pool, org, "target", "agent")
	cert := insertCert(t, pool, org, "cert", "cert.example.test", nil)
	version := insertVersion(t, pool, cert, time.Now().Add(90*24*time.Hour), uuid.Nil)
	grantID := insertAgentGrant(t, pool, client, cert, target, "drift", version, "")

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "deploy.drift"); got != 1 {
		t.Fatalf("events after scan 1 = %d, want 1", got)
	}

	// Prune deletes the dedupe row once the condition ages past retention
	// (standing in for the passage of time the real hourly prune needs,
	// same convention as TestExpiredScanRespectsRetentionWindow).
	if _, err := pool.Exec(ctx, `DELETE FROM notification_events WHERE dedupe_key = $1`,
		fmt.Sprintf("deploy.drift:%s:%s", grantID, version)); err != nil {
		t.Fatal(err)
	}

	// A very recent agent report keeps updated_at fresh, even though the
	// grant has been drifted since real "now" (state_changed_at, left
	// untouched by this raw UPDATE) — exactly the case a bound on
	// updated_at gets wrong. Queried directly against the scan (rather
	// than through a second s.Scan, whose own Prune step — run with a
	// far-future s.Now — would immediately delete a freshly re-emitted
	// row again and mask the very re-emission this test is checking for)
	// so the assertion is only about what the scan query itself returns.
	future := time.Now().Add(notify.EventRetention + 24*time.Hour)
	if _, err := pool.Exec(ctx, `UPDATE deployments SET updated_at = $2 WHERE grant_id = $1`,
		grantID, future.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	rows, err := q.ScanFailedOrDriftedDeployments(ctx, sqlcgen.ScanFailedOrDriftedDeploymentsParams{
		Since: future.Add(-notify.EventRetention), PageLimit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("ScanFailedOrDriftedDeployments rows = %d, want 0 (a still-ongoing drift older than the retention window, kept only artificially 'recent' by repeated reports, must not re-emit)", len(rows))
	}
}

// TestClientOfflineOncePerEpisode: a client last seen before the offline
// cutoff emits once; scanning again with the same last_seen is a no-op;
// reconnecting (last_seen bumped) and then going offline again is a fresh
// episode and emits again.
func TestClientOfflineOncePerEpisode(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})
	setAgentsOfflineAfterSeconds(t, pool, 180)

	target := insertDeployTarget(t, pool, org, "target", "agent")
	cert := insertCert(t, pool, org, "cert", "cert.example.test", nil)
	version := insertVersion(t, pool, cert, time.Now().Add(90*24*time.Hour), uuid.Nil)

	lastSeen := time.Now().Add(-10 * time.Minute)
	client := insertClient(t, pool, org, "client-1", clientOpts{lastSeen: &lastSeen})
	insertAgentGrant(t, pool, client, cert, target, "ok", version, "")

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "client.offline"); got != 1 {
		t.Fatalf("events after scan 1 = %d, want 1", got)
	}

	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "client.offline"); got != 1 {
		t.Fatalf("events after scan 2 (same episode) = %d, want still 1", got)
	}

	// Reconnect, then go offline again: a fresh episode.
	reconnected := time.Now()
	if _, err := pool.Exec(ctx, "UPDATE clients SET last_seen = $2 WHERE id = $1", client, reconnected); err != nil {
		t.Fatal(err)
	}
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "client.offline"); got != 1 {
		t.Fatalf("events while reconnected = %d, want still 1", got)
	}

	// A distinctly different offset from the first episode's lastSeen (not
	// just "10 minutes ago" again): the dedupe key is keyed on last_seen's
	// own Unix second, and a fast-running test can otherwise land both
	// episodes in the same second by coincidence.
	wentOfflineAgain := time.Now().Add(-30 * time.Minute)
	if _, err := pool.Exec(ctx, "UPDATE clients SET last_seen = $2 WHERE id = $1", client, wentOfflineAgain); err != nil {
		t.Fatal(err)
	}
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "client.offline"); got != 2 {
		t.Fatalf("events after going offline again = %d, want 2", got)
	}
}

func TestAgentCertExpiring(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	soon := time.Now().Add(5 * 24 * time.Hour)
	insertClient(t, pool, org, "expiring", clientOpts{agentCertSerial: "aa11", agentCertNotAfter: &soon})

	far := time.Now().Add(60 * 24 * time.Hour)
	insertClient(t, pool, org, "not-expiring", clientOpts{agentCertSerial: "bb22", agentCertNotAfter: &far})

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "agent.cert_expiring"); got != 1 {
		t.Fatalf("events = %d, want 1", got)
	}
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "agent.cert_expiring"); got != 1 {
		t.Fatalf("events after scan 2 = %d, want still 1", got)
	}
}

// TestAgentCertExpiringDoesNotReemitAfterPrune (final review fix wave,
// finding 1): agent.cert_expiring is emitted up to AgentCertExpiryWindow
// (14d) before the certificate's own not_after, so its dedupe row is
// pruned around not_after + (EventRetention - AgentCertExpiryWindow) =
// not_after + 76d, not not_after + 90d. Bounding the scan's own since on
// the full 90-day EventRetention (the same value every other scan uses)
// left a 14-day gap — between +76d and +90d — where the dedupe row was
// already pruned but the scan's own since bound still matched, re-emitting
// the same condition a second time.
func TestAgentCertExpiringDoesNotReemitAfterPrune(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	notAfter := time.Now().Add(5 * 24 * time.Hour)
	clientID := insertClient(t, pool, org, "expiring", clientOpts{agentCertSerial: "aa11", agentCertNotAfter: &notAfter})

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "agent.cert_expiring"); got != 1 {
		t.Fatalf("events after scan 1 = %d, want 1", got)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM notification_events WHERE dedupe_key = $1`,
		fmt.Sprintf("agent.cert_expiring:%s:aa11", clientID)); err != nil {
		t.Fatal(err)
	}

	// 82 days after not_after - 5d: past not_after + 76d (where the
	// fixed since bound excludes it) but still well inside not_after +
	// 90d (where the old, EventRetention-wide bound would not).
	future := time.Now().Add(82 * 24 * time.Hour)
	s.Now = func() time.Time { return future }

	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got := eventCount(t, pool, "agent.cert_expiring"); got != 0 {
		t.Fatalf("agent.cert_expiring events after prune + 82d = %d, want 0 (must not re-emit)", got)
	}
}

func TestEventsPruned(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)

	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_events (org_id, kind, severity, resource_type, resource_id, resource_name, summary, dedupe_key, at)
		 VALUES ($1, 'test', 'info', 'channel', 'c1', 'old', 'old event', 'test:old', now() - interval '91 days')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_events (org_id, kind, severity, resource_type, resource_id, resource_name, summary, dedupe_key, at)
		 VALUES ($1, 'test', 'info', 'channel', 'c2', 'recent', 'recent event', 'test:recent', now() - interval '1 day')`, org); err != nil {
		t.Fatal(err)
	}

	s := newSources(pool, &fakeInserter{})
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}

	if got := countRows(t, pool, "notification_events", "dedupe_key = $1", "test:old"); got != 0 {
		t.Fatalf("old event rows = %d, want 0 (pruned)", got)
	}
	if got := countRows(t, pool, "notification_events", "dedupe_key = $1", "test:recent"); got != 1 {
		t.Fatalf("recent event rows = %d, want 1 (kept)", got)
	}
}
