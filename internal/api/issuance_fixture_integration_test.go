//go:build integration

package api

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
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
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/signer"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
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
	srv   *Server
	pool  *pgxpool.Pool
	store *issuance.Store
	certs *certstore.Store
	org   uuid.UUID
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
	store := issuance.NewStore(pool, box, settingsStore)
	certs := certstore.New(pool, box)
	aud := audit.New(pool, bytes.Repeat([]byte{5}, 32))
	svc := issuance.NewService(store, certs, &fakeJobs{queued: map[uuid.UUID]bool{}})
	svc.NewRegistrar = func(issuance.CA) issuance.Registrar { return &fakeRegistrar{} }
	svc.Auditor = aud
	svc.Log = slog.Default()
	srv := &Server{d: Deps{Log: slog.Default(), Pool: pool, Auditor: aud, Issuance: svc, Certs: certs,
		Settings: settingsStore, Sections: sections}}
	return &apiFixture{srv: srv, pool: pool, store: store, certs: certs, org: dbtest.Org(t, pool)}
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
