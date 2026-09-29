//go:build integration

package monitor_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/monitor"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
)

// newSettingsStore builds a settings.Store against pool, sealing secrets
// with a fixed test key (same pattern as internal/notify's own
// helpers_integration_test.go/sources_helpers_integration_test.go).
func newSettingsStore(pool *pgxpool.Pool) *settings.Store {
	key := bytes.Repeat([]byte{9}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	return settings.NewStore(sqlcgen.New(pool), env)
}

// allowLoopback writes the "notifications" section with allowLoopbackUrls
// true, so Service.Check/Observe may dial 127.0.0.1 fixtures (Deviations
// R5: monitors share the notifier SSRF policy).
func allowLoopback(t *testing.T, store *settings.Store) {
	t.Helper()
	if err := store.Set(context.Background(), settings.SectionKey(notify.SectionName),
		notify.Settings{AllowLoopbackURLs: true, ExpiryWarningDays: 7, FailureThreshold: 3}); err != nil {
		t.Fatalf("set notifications settings: %v", err)
	}
}

// newService builds a monitor.Service against pool with a real Store, an
// Emitter backed by ins, and the notifications settings store.
func newService(pool *pgxpool.Pool, ins notify.Inserter) *monitor.Service {
	return &monitor.Service{
		Store:    &monitor.Store{Pool: pool, Q: sqlcgen.New(pool)},
		Emitter:  &notify.Emitter{Pool: pool, River: ins},
		Settings: newSettingsStore(pool),
	}
}

// fakeNotifyInserter is notify.Inserter backed by memory (same shape as
// internal/notify's own fakeInserter): records every enqueued
// DeliverArgs, letting a test assert how many events actually matched a
// channel without needing a live river worker.
type fakeNotifyInserter struct {
	mu    sync.Mutex
	calls []notify.DeliverArgs
}

func (f *fakeNotifyInserter) InsertTx(_ context.Context, _ pgx.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if da, ok := args.(notify.DeliverArgs); ok {
		f.calls = append(f.calls, da)
	}
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}}, nil
}

// fakeMonitorInserter is monitor.Inserter backed by memory: records every
// enqueued CheckArgs (EnqueueDueChecks' own job), for TestScanEnqueuesDueOnly.
type fakeMonitorInserter struct {
	mu    sync.Mutex
	calls []monitor.CheckArgs
}

func (f *fakeMonitorInserter) Insert(_ context.Context, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ca, ok := args.(monitor.CheckArgs)
	if !ok {
		return nil, fmt.Errorf("monitor test: unexpected job args %T", args)
	}
	f.calls = append(f.calls, ca)
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}}, nil
}

func (f *fakeMonitorInserter) ids() []uuid.UUID {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uuid.UUID, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.MonitorID
	}
	return out
}

// monitorRow is insertMonitor's own input; zero values give sensible
// defaults (enabled, state unknown, due now, interval 3600s).
type monitorRow struct {
	orgID          uuid.UUID
	name           string
	host           string
	port           int
	sni            *string
	state          string
	nextCheckAt    time.Time
	enabled        *bool // nil means true
	expectedCertID *uuid.UUID
}

// insertMonitor inserts an external_monitors row directly (bypassing
// Store.Create's validation, so a test can set state/nextCheckAt/enabled
// precisely) and returns its id.
func insertMonitor(t *testing.T, pool *pgxpool.Pool, m monitorRow) uuid.UUID {
	t.Helper()
	if m.name == "" {
		m.name = "monitor-" + uuid.NewString()[:8]
	}
	if m.port == 0 {
		m.port = 443
	}
	if m.state == "" {
		m.state = "unknown"
	}
	if m.nextCheckAt.IsZero() {
		m.nextCheckAt = time.Now().Add(-time.Minute)
	}
	enabled := true
	if m.enabled != nil {
		enabled = *m.enabled
	}
	var id uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO external_monitors (org_id, name, host, port, sni, interval_seconds, expected_cert_id, enabled, state, state_changed_at, next_check_at)
		VALUES ($1, $2, $3, $4, $5, 3600, $6, $7, $8, now(), $9)
		RETURNING id`,
		m.orgID, m.name, m.host, m.port, m.sni, m.expectedCertID, enabled, m.state, m.nextCheckAt).Scan(&id)
	if err != nil {
		t.Fatalf("insert monitor: %v", err)
	}
	return id
}

func getMonitorState(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var state string
	if err := pool.QueryRow(context.Background(), "SELECT state FROM external_monitors WHERE id = $1", id).Scan(&state); err != nil {
		t.Fatalf("get monitor state: %v", err)
	}
	return state
}

func eventCount(t *testing.T, pool *pgxpool.Pool, kind string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM notification_events WHERE kind = $1", kind).Scan(&n); err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

// selfSignedCert returns a real, x509-parseable self-signed certificate.
func selfSignedCert(t *testing.T, cn string, notAfter time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// listenTLS starts a long-lived TLS server on 127.0.0.1 presenting
// leafDER/key, returning its port; it keeps accepting connections until
// the test ends.
func listenTLS(t *testing.T, leafDER []byte, key *ecdsa.PrivateKey) int {
	t.Helper()
	cert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.(*tls.Conn).Handshake()
				time.Sleep(200 * time.Millisecond)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// insertCertWithFingerprint inserts a certificate (and its sole, current
// version) whose sha256_fp is fp — a monitor with no expectedCertificateId
// mismatches unless the observed leaf matches some certificate's current
// version in the org (batch-3 review finding 1), so a test exercising the
// "ok"/"expiring" path with no expectedCertificateId set needs one of
// these seeded first.
func insertCertWithFingerprint(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, name, fp string, notAfter time.Time) uuid.UUID {
	t.Helper()
	var certID uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO certificates (org_id, name, common_name, sans) VALUES ($1, $2, $2, '{}') RETURNING id`,
		orgID, name).Scan(&certID); err != nil {
		t.Fatalf("insert certificate: %v", err)
	}
	var versionID uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der, source)
		VALUES ($1, $2, now() - interval '1 day', $3, $4, 'ec256', 'leaf', 'issued') RETURNING id`,
		certID, uuid.NewString()[:12], notAfter, fp).Scan(&versionID); err != nil {
		t.Fatalf("insert certificate_version: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE certificates SET current_version_id = $2, status = 'active' WHERE id = $1`, certID, versionID); err != nil {
		t.Fatalf("set current version: %v", err)
	}
	return certID
}
