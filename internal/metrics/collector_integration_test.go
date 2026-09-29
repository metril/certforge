//go:build integration

package metrics_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/metrics"
	"github.com/metril/certforge/internal/settings"
)

// setSetting writes a plain (unencrypted) settings value, the same column
// Collector's store.Get reads — Collector never touches a section's secret
// column, so no envelope encryption is needed for these rows.
func setSetting(ctx context.Context, t *testing.T, q *sqlcgen.Queries, key, value string) {
	t.Helper()
	if err := q.UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: key, Value: []byte(value)}); err != nil {
		t.Fatal(err)
	}
}

// newStore returns a *settings.Store good enough for Collector's plain
// Get calls (the only thing it does with store); the envelope key is
// otherwise unused since nothing here writes a secret.
func newStore(q *sqlcgen.Queries) *settings.Store {
	key := bytes.Repeat([]byte{7}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	return settings.NewStore(q, env)
}

// TestCollectorSeries seeds one of everything Collector queries (Shared
// contract, Metrics row) and asserts every series family is present, with
// spot-checked values: an org, a certificate with a current version (due
// for renewal), two clients (one recently seen, one stale), an agent-run
// grant/deployment, a server-run grant/deployment, an external monitor,
// the "agents" settings section, a backup.status row, a crypto.rewrap row
// and one non-completed river job.
func TestCollectorSeries(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)

	slug := "acme-" + uuid.NewString()[:8]
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug, name) VALUES ($1, $1) RETURNING id`, slug).Scan(&orgID); err != nil {
		t.Fatal(err)
	}

	var certID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO certificates (org_id, name, common_name, status, managed, next_renew_at)
		VALUES ($1, 'web', 'web.example.test', 'active', true, now() - interval '1 hour') RETURNING id`, orgID).Scan(&certID); err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(60 * 24 * time.Hour).UTC()
	var versionID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der, private_key)
		VALUES ($1, 'serial-1', now(), $2, 'fp', 'ec256', '\x00', '\x00') RETURNING id`, certID, notAfter).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE certificates SET current_version_id = $2 WHERE id = $1`, certID, versionID); err != nil {
		t.Fatal(err)
	}

	var onlineClientID, offlineClientID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO clients (org_id, name, status, last_seen) VALUES ($1, 'agent-1', 'active', now()) RETURNING id`,
		orgID).Scan(&onlineClientID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO clients (org_id, name, status, last_seen) VALUES ($1, 'agent-2', 'active', now() - interval '1 hour') RETURNING id`,
		orgID).Scan(&offlineClientID); err != nil {
		t.Fatal(err)
	}

	var specID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO output_specs (org_id, name) VALUES ($1, 'layout') RETURNING id`, orgID).Scan(&specID); err != nil {
		t.Fatal(err)
	}
	var targetID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO deploy_targets (org_id, name, type, config) VALUES ($1, 'traefik-1', 'traefik', '{}') RETURNING id`,
		orgID).Scan(&targetID); err != nil {
		t.Fatal(err)
	}

	var agentGrantID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO client_cert_grants (client_id, cert_id, output_spec_id) VALUES ($1, $2, $3) RETURNING id`,
		onlineClientID, certID, specID).Scan(&agentGrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (grant_id, state) VALUES ($1, 'ok')`, agentGrantID); err != nil {
		t.Fatal(err)
	}

	var serverGrantID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO client_cert_grants (cert_id, deploy_target_id) VALUES ($1, $2) RETURNING id`,
		certID, targetID).Scan(&serverGrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO server_deployments (grant_id, status) VALUES ($1, 'deployed')`, serverGrantID); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO external_monitors (org_id, name, host, state) VALUES ($1, 'mon-1', 'example.test', 'ok')`, orgID); err != nil {
		t.Fatal(err)
	}

	setSetting(ctx, t, q, "section.agents", `{"offlineAfterSeconds":60}`)
	lastSuccess := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	setSetting(ctx, t, q, "backup.status", `{"lastSuccessAt":"`+lastSuccess+`"}`)
	setSetting(ctx, t, q, settings.RewrapKey, `{"remaining":3}`)

	if _, err := pool.Exec(ctx, `INSERT INTO river_job (state, attempt, max_attempts, priority, args, kind)
		VALUES ('available', 0, 3, 1, '{}', 'certforge_issue')`); err != nil {
		t.Fatal(err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewCollector(pool, newStore(q), "1.2.3-test"))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	families := map[string]bool{}
	for _, mf := range mfs {
		families[mf.GetName()] = true
	}
	for _, want := range []string{
		"certforge_certificates",
		"certforge_certificate_not_after_seconds",
		"certforge_certificates_due_renewal",
		"certforge_clients",
		"certforge_deployments",
		"certforge_monitors",
		"certforge_river_jobs",
		"certforge_backup_last_success_timestamp_seconds",
		"certforge_kek_rewrap_remaining",
		"certforge_build_info",
	} {
		if !families[want] {
			t.Errorf("missing series family %q", want)
		}
	}

	if got := sample(t, mfs, "certforge_clients", map[string]string{"org": slug, "status": "online"}); got != 1 {
		t.Errorf("clients online = %v, want 1", got)
	}
	if got := sample(t, mfs, "certforge_clients", map[string]string{"org": slug, "status": "offline"}); got != 1 {
		t.Errorf("clients offline = %v, want 1", got)
	}
	if got := sample(t, mfs, "certforge_certificates_due_renewal", map[string]string{"org": slug}); got != 1 {
		t.Errorf("due renewal = %v, want 1", got)
	}
	if got := sample(t, mfs, "certforge_deployments", map[string]string{"org": slug, "status": "ok"}); got != 2 {
		t.Errorf("deployments ok (agent+server summed) = %v, want 2", got)
	}
	if got := sample(t, mfs, "certforge_monitors", map[string]string{"org": slug, "state": "ok"}); got != 1 {
		t.Errorf("monitors ok = %v, want 1", got)
	}
	if got := sample(t, mfs, "certforge_certificate_not_after_seconds", map[string]string{"org": slug, "certificate": certID.String()}); got != float64(notAfter.Unix()) {
		t.Errorf("not_after = %v, want %v", got, notAfter.Unix())
	}
	if got := sample(t, mfs, "certforge_build_info", map[string]string{"version": "1.2.3-test"}); got != 1 {
		t.Errorf("build_info = %v, want 1", got)
	}
	if got := sample(t, mfs, "certforge_kek_rewrap_remaining", nil); got != 3 {
		t.Errorf("rewrap remaining = %v, want 3", got)
	}
	if got := sample(t, mfs, "certforge_backup_last_success_timestamp_seconds", nil); got == 0 {
		t.Errorf("backup last success = %v, want nonzero", got)
	}
}

// TestCollectorCaches: a second scrape within CacheTTL reuses the first
// snapshot instead of re-querying — a certificate inserted between two
// Gather calls must not show up in the second (Shared contract: one query
// set per CacheTTL).
func TestCollectorCaches(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)

	slug := "cache-" + uuid.NewString()[:8]
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug, name) VALUES ($1, $1) RETURNING id`, slug).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO certificates (org_id, name, common_name, status) VALUES ($1, 'one', 'one.example.test', 'pending')`, orgID); err != nil {
		t.Fatal(err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewCollector(pool, newStore(q), "test"))

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	before := sample(t, mfs, "certforge_certificates", map[string]string{"org": slug, "status": "pending"})
	if before != 1 {
		t.Fatalf("before = %v, want 1", before)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO certificates (org_id, name, common_name, status) VALUES ($1, 'two', 'two.example.test', 'pending')`, orgID); err != nil {
		t.Fatal(err)
	}

	mfs, err = reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if after := sample(t, mfs, "certforge_certificates", map[string]string{"org": slug, "status": "pending"}); after != before {
		t.Fatalf("second scrape within CacheTTL = %v, want cached %v (unaffected by the new row)", after, before)
	}
}

// sample finds the single metric in mfs whose family is name and whose
// labels exactly match want (nil matches an unlabelled family), t.Fatal-ing
// if there isn't exactly one match.
func sample(t *testing.T, mfs []*dto.MetricFamily, name string, want map[string]string) float64 {
	t.Helper()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labelsEqual(labels, want) {
				if g := m.GetGauge(); g != nil {
					return g.GetValue()
				}
				if c := m.GetCounter(); c != nil {
					return c.GetValue()
				}
			}
		}
	}
	t.Fatalf("no sample for %s%v", name, want)
	return 0
}

func labelsEqual(got, want map[string]string) bool {
	if len(want) != len(got) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}
