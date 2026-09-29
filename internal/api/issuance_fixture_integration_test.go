//go:build integration

package api

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/signer"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
	"github.com/metril/certforge/internal/vault"
)

type fakeJobs struct{ queued map[uuid.UUID]bool }

func (j *fakeJobs) Insert(_ context.Context, a river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	id := a.(issuance.IssueArgs).CertID
	dup := j.queued[id]
	j.queued[id] = true
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}, UniqueSkippedAsDuplicate: dup}, nil
}

// fakeRegistrar stands in for the real ACME signer so account registration
// tests never reach a live CA.
type fakeRegistrar struct{ n int }

func (r *fakeRegistrar) Register(_ context.Context, email string, _ *acmesigner.EAB) (signer.AccountMaterial, error) {
	r.n++
	return signer.AccountMaterial{Email: email, KeyPKCS8: []byte("k"), RegistrationURI: "https://ca.test/acct/fake"}, nil
}

type apiFixture struct {
	srv           *Server
	pool          *pgxpool.Pool
	store         *issuance.Store
	certs         *certstore.Store
	box           crypto.Box
	org           uuid.UUID
	settingsStore *settings.Store
	sections      *settings.Registry
	deployJobs    *fakeDeployJobs
}

// fakeDeployJobs is a deploy.Inserter recording every certforge_server_deploy
// job InsertTx receives, so a test can assert what was enqueued and then
// drive Dispatcher.Deploy directly (these fixtures run no live river
// worker loop).
type fakeDeployJobs struct {
	mu      sync.Mutex
	queued  map[string]bool // "grantID|versionID" while not completed
	inserts []deploy.DeployArgs
}

func newFakeDeployJobs() *fakeDeployJobs { return &fakeDeployJobs{queued: map[string]bool{}} }

func (j *fakeDeployJobs) InsertTx(_ context.Context, _ pgx.Tx, a river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	da := a.(deploy.DeployArgs)
	key := da.GrantID.String() + "|" + da.VersionID.String()
	j.mu.Lock()
	defer j.mu.Unlock()
	dup := j.queued[key]
	j.queued[key] = true
	j.inserts = append(j.inserts, da)
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}, UniqueSkippedAsDuplicate: dup}, nil
}

// count returns how many times a DeployArgs{grantID, versionID} was
// inserted (including duplicates skipped by uniqueness).
func (j *fakeDeployJobs) count(grantID, versionID uuid.UUID) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := 0
	for _, a := range j.inserts {
		if a.GrantID == grantID && a.VersionID == versionID {
			n++
		}
	}
	return n
}

// setVaultSettings stores raw as the "vault" global settings section
// (bypassing HTTP, this fixture has no server to send a request to), for a
// test that points the section at a fake Vault httptest server.
func (f *apiFixture) setVaultSettings(t *testing.T, raw string) {
	t.Helper()
	ctx := context.Background()
	sec, ok := f.sections.Section(vault.SectionName)
	if !ok {
		t.Fatal("vault section not registered")
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := f.settingsStore.PutSectionTx(ctx, tx, sec, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	pool, q := dbtest.New(t)
	box := cryptotest.PrefixBox{}
	// The global issuance_defaults settings section is validated through
	// issuance.Store, so global settings need a real (if throwaway) Envelope
	// rather than the PrefixBox stand-in the issuance/certstore boxes use.
	key := bytes.Repeat([]byte{7}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	settingsStore := settings.NewStore(q, env)
	sections := settings.DefaultRegistry()
	if err := issuance.RegisterSettings(sections); err != nil {
		t.Fatal(err)
	}
	if err := vault.RegisterSettings(sections); err != nil {
		t.Fatal(err)
	}
	vaultProvider := vault.NewProvider(settingsStore, sections)
	deployReg := deploy.NewRegistry()
	deployReg.Register("Vault KV (runs on server)", deploy.VaultKV{Vault: vaultProvider})
	store := issuance.NewStore(pool, box, settingsStore)
	store.SetVault(vaultProvider)
	certs := certstore.New(pool, box)
	aud := audit.New(pool, bytes.Repeat([]byte{5}, 32))
	svc := issuance.NewService(store, certs, &fakeJobs{queued: map[uuid.UUID]bool{}})
	svc.NewRegistrar = func(issuance.CA) issuance.Registrar { return &fakeRegistrar{} }
	svc.Auditor = aud
	svc.Log = slog.Default()
	deployJobs := newFakeDeployJobs()
	dispatcher := &deploy.Dispatcher{Pool: pool, Q: q, Reg: deployReg, Certs: certs, River: deployJobs, Log: slog.Default()}
	srv := &Server{d: Deps{Log: slog.Default(), Pool: pool, Queries: q, Auditor: aud, Issuance: svc, Certs: certs, Box: box,
		Settings: settingsStore, Sections: sections, Vault: vaultProvider, Deploy: deployReg, Dispatcher: dispatcher}}
	return &apiFixture{srv: srv, pool: pool, store: store, certs: certs, box: box, org: dbtest.Org(t, pool),
		settingsStore: settingsStore, sections: sections, deployJobs: deployJobs}
}

// as returns a context for a user holding role in the fixture org; admin is
// bound globally, as 1A's bootstrap admin is.
func (f *apiFixture) as(role string) context.Context {
	b := authn.Binding{Role: role, OrgID: &f.org}
	if role == authz.RoleAdmin {
		b.OrgID = nil
	}
	return authn.WithPrincipal(context.Background(), authn.Principal{Kind: authn.KindUser, UserID: uuid.New(),
		Roles: []string{role}, Bindings: []authn.Binding{b}, OrgIDs: []uuid.UUID{f.org}})
}

// issuedCert stores a certificate with one version whose key is "secret-key".
//
//nolint:unused // used by Task 14's certificate handler tests.
func (f *apiFixture) issuedCert(t *testing.T, name string) (issuance.Certificate, certstore.Version) {
	t.Helper()
	ctx := context.Background()
	c, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{Name: name, CommonName: name + ".example.test"})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.certs.Insert(ctx, tx, c.ID, &signer.Issued{LeafDER: []byte("leaf"), ChainDER: [][]byte{[]byte("int")},
		PrivateKeyPKCS8: []byte("secret-key"), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Serial: "01"}, "ec256", certstore.InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return c, v
}

// secondVersion inserts a second certificate_versions row for an existing
// certID and makes it current, returning its id: TestServerGrantLifecycle
// (Task 11) uses this to exercise a new version enqueuing a fresh server
// deploy, the same way agents.syncFixture.version/setCurrent do for a
// client grant's own re-render tests.
func (f *apiFixture) secondVersion(t *testing.T, certID uuid.UUID, serial string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	tx, err := f.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.certs.Insert(ctx, tx, certID, &signer.Issued{LeafDER: []byte("leaf-" + serial), ChainDER: [][]byte{[]byte("int-" + serial)},
		PrivateKeyPKCS8: []byte("secret-key-" + serial), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Serial: serial},
		"ec256", certstore.InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE certificates SET current_version_id = $2 WHERE id = $1`, certID, v.ID); err != nil {
		t.Fatal(err)
	}
	return v.ID
}

func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	if got := problemStatus(err); got != status {
		t.Fatalf("want problem %d, got %v", status, err)
	}
}

func (f *apiFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// lastAuditDetails returns the most recent details JSON (as text) for
// action against resourceID.
func (f *apiFixture) lastAuditDetails(t *testing.T, action, resourceID string) string {
	t.Helper()
	var details string
	err := f.pool.QueryRow(context.Background(),
		`SELECT details::text FROM audit_events WHERE action = $1 AND resource_id = $2 ORDER BY id DESC LIMIT 1`, action, resourceID).Scan(&details)
	if err != nil {
		t.Fatal(err)
	}
	return details
}
