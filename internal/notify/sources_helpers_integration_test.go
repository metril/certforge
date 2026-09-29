//go:build integration

package notify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
)

// newSettingsStore builds a settings.Store against pool, sealing secrets
// with a fixed test key (no secrets are exercised by these tests, but
// Sources.Scan/Current/offlineCutoff both read through a real Store, the
// same as notifyFixture in internal/api).
func newSettingsStore(pool *pgxpool.Pool) *settings.Store {
	key := bytes.Repeat([]byte{9}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	return settings.NewStore(sqlcgen.New(pool), env)
}

// setNotifySettings writes the "notifications" section directly (bypassing
// the registry: these tests only need Sources' own reads of it, not PUT
// validation). Zero values are replaced with the schema's own defaults so
// a test only overriding one field doesn't accidentally zero the other.
func setNotifySettings(t *testing.T, pool *pgxpool.Pool, failureThreshold, expiryWarningDays int) {
	t.Helper()
	if failureThreshold == 0 {
		failureThreshold = 3
	}
	if expiryWarningDays == 0 {
		expiryWarningDays = 7
	}
	v, _ := json.Marshal(notify.Settings{FailureThreshold: failureThreshold, ExpiryWarningDays: expiryWarningDays})
	putSettingsSection(t, pool, "notifications", v)
}

// setAgentsOfflineAfterSeconds writes just enough of the "agents" section
// for Sources.offlineCutoff to resolve a non-default offlineAfterSeconds.
func setAgentsOfflineAfterSeconds(t *testing.T, pool *pgxpool.Pool, seconds int) {
	t.Helper()
	v, _ := json.Marshal(map[string]any{"offlineAfterSeconds": seconds, "heartbeatSeconds": 60})
	putSettingsSection(t, pool, "agents", v)
}

func putSettingsSection(t *testing.T, pool *pgxpool.Pool, name string, value []byte) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO settings (key, value) VALUES ($1, $2::jsonb)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		"section."+name, value)
	if err != nil {
		t.Fatalf("put settings section %s: %v", name, err)
	}
}

// insertCA inserts a minimal CA row and returns its id.
func insertCA(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO cas (org_id, name, preset, directory_url) VALUES ($1, $2, 'custom', 'https://ca.test/dir') RETURNING id`,
		orgID, name).Scan(&id)
	if err != nil {
		t.Fatalf("insert ca: %v", err)
	}
	return id
}

// insertCert inserts a certificate row (no version, no current_version_id).
func insertCert(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, name, commonName string, sans []string) uuid.UUID {
	t.Helper()
	if sans == nil {
		sans = []string{}
	}
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO certificates (org_id, name, common_name, sans) VALUES ($1, $2, $3, $4) RETURNING id`,
		orgID, name, commonName, sans).Scan(&id)
	if err != nil {
		t.Fatalf("insert certificate: %v", err)
	}
	return id
}

// insertVersion inserts a certificate_versions row (leaf_der/sha256_fp are
// dummy bytes: Sources never parses them, only reads columns) and returns
// its id. caID may be uuid.Nil for none.
func insertVersion(t *testing.T, pool *pgxpool.Pool, certID uuid.UUID, notAfter time.Time, caID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var ca *uuid.UUID
	if caID != uuid.Nil {
		ca = &caID
	}
	err := pool.QueryRow(context.Background(),
		`INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der, source, ca_id)
		 VALUES ($1, $2, now() - interval '1 day', $3, 'fp', 'ec256', 'leaf', 'issued', $4) RETURNING id`,
		certID, uuid.NewString()[:12], notAfter, ca).Scan(&id)
	if err != nil {
		t.Fatalf("insert certificate_version: %v", err)
	}
	return id
}

// setCurrentVersion makes versionID certID's current_version_id (active status).
func setCurrentVersion(t *testing.T, pool *pgxpool.Pool, certID, versionID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE certificates SET current_version_id = $2, status = 'active' WHERE id = $1`,
		certID, versionID); err != nil {
		t.Fatalf("set current version: %v", err)
	}
}

// insertClient inserts a clients row.
type clientOpts struct {
	status            string
	lastSeen          *time.Time
	agentCertSerial   string
	agentCertNotAfter *time.Time
}

func insertClient(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, name string, o clientOpts) uuid.UUID {
	t.Helper()
	if o.status == "" {
		o.status = "active"
	}
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO clients (org_id, name, status, last_seen, agent_cert_serial, agent_cert_not_after)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		orgID, name, o.status, o.lastSeen, o.agentCertSerial, o.agentCertNotAfter).Scan(&id)
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	return id
}

// insertDeployTarget inserts a deploy_targets row; runsOn is "agent"
// (type traefik) or "server" (type vault-kv) — the two combinations the
// deploy_targets_type_runs_on_check constraint allows.
func insertDeployTarget(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, name, runsOn string) uuid.UUID {
	t.Helper()
	typ := "traefik"
	if runsOn == "server" {
		typ = "vault-kv"
	}
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO deploy_targets (org_id, name, type, runs_on) VALUES ($1, $2, $3, $4) RETURNING id`,
		orgID, name, typ, runsOn).Scan(&id)
	if err != nil {
		t.Fatalf("insert deploy_target: %v", err)
	}
	return id
}

// insertAgentGrant inserts a live client_cert_grants row for an agent-run
// deployment, plus its 1:1 deployments row in state/versionID.
func insertAgentGrant(t *testing.T, pool *pgxpool.Pool, clientID, certID, targetID uuid.UUID, state string, versionID uuid.UUID, errText string) uuid.UUID {
	t.Helper()
	var grantID uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO client_cert_grants (client_id, cert_id, deploy_target_id) VALUES ($1, $2, $3) RETURNING id`,
		clientID, certID, targetID).Scan(&grantID)
	if err != nil {
		t.Fatalf("insert client grant: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO deployments (grant_id, version_id, state, error) VALUES ($1, $2, $3, $4)`,
		grantID, versionID, state, errText); err != nil {
		t.Fatalf("insert deployment: %v", err)
	}
	return grantID
}

// insertServerGrant inserts a live client-less client_cert_grants row for
// a server-run deployment, plus its 1:1 server_deployments row.
func insertServerGrant(t *testing.T, pool *pgxpool.Pool, certID, targetID uuid.UUID, status string, versionID uuid.UUID, lastError string) uuid.UUID {
	t.Helper()
	var grantID uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO client_cert_grants (cert_id, deploy_target_id) VALUES ($1, $2) RETURNING id`,
		certID, targetID).Scan(&grantID)
	if err != nil {
		t.Fatalf("insert server grant: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO server_deployments (grant_id, version_id, status, last_error) VALUES ($1, $2, $3, $4)`,
		grantID, versionID, status, lastError); err != nil {
		t.Fatalf("insert server_deployment: %v", err)
	}
	return grantID
}

// eventCount returns how many notification_events rows exist for kind.
func eventCount(t *testing.T, pool *pgxpool.Pool, kind string) int {
	t.Helper()
	return countRows(t, pool, "notification_events", "kind = $1", kind)
}

// eventDetails returns the raw details jsonb (as a string) for the sole
// event with the given dedupe_key.
func eventDetails(t *testing.T, pool *pgxpool.Pool, dedupeKey string) string {
	t.Helper()
	var d []byte
	if err := pool.QueryRow(context.Background(), "SELECT details::text FROM notification_events WHERE dedupe_key = $1", dedupeKey).Scan(&d); err != nil {
		t.Fatalf("query details: %v", err)
	}
	return string(d)
}
