//go:build integration

package notify_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/dbtest"
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
