//go:build integration

package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/signer"
)

// fakeGlobal serves the global settings section from memory.
type fakeGlobal struct{ d Defaults }

func (f fakeGlobal) Get(_ context.Context, _ string, out any) error {
	b, _ := json.Marshal(f.d)
	return json.Unmarshal(b, out)
}

type fixture struct {
	pool  *pgxpool.Pool
	store *Store
	org   uuid.UUID
	ca    CA
	acct  Account
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool, _ := dbtest.New(t)
	f := &fixture{pool: pool, org: dbtest.Org(t, pool)}
	f.store = NewStore(pool, cryptotest.PrefixBox{}, fakeGlobal{})
	ctx := context.Background()
	var err error
	f.ca, err = f.store.CreateCA(ctx, f.org, CAInput{Name: "Pebble", Preset: "custom", DirectoryURL: "https://pebble.test/dir", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	f.acct, err = f.store.InsertAccount(ctx, f.org, f.ca.ID, signer.AccountMaterial{Email: "ops@example.test", KeyPKCS8: der, RegistrationURI: "https://pebble.test/acct/1"})
	if err != nil {
		t.Fatal(err)
	}
	ca, acct := f.ca.ID, f.acct.ID
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{CAID: &ca, AccountID: &acct}); err != nil {
		t.Fatal(err)
	}
	return f
}

// client inserts an active client row directly (this package must not
// import internal/agents), for a rule's clientId.
func (f *fixture) client(t *testing.T, org uuid.UUID, name string, capabilities []string) uuid.UUID {
	t.Helper()
	if capabilities == nil {
		capabilities = []string{}
	}
	var id uuid.UUID
	err := f.pool.QueryRow(context.Background(),
		`INSERT INTO clients (org_id, name, status, capabilities) VALUES ($1, $2, 'active', $3) RETURNING id`,
		org, name, capabilities).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// account registers a fresh ACME account against caID, for tests that issue
// against a CA other than the fixture's default one.
func (f *fixture) account(t *testing.T, caID uuid.UUID) uuid.UUID {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	a, err := f.store.InsertAccount(context.Background(), f.org, caID,
		signer.AccountMaterial{Email: "ops@example.test", KeyPKCS8: der, RegistrationURI: "https://ca.test/acct/" + caID.String()})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func (f *fixture) credential(t *testing.T, name string) uuid.UUID {
	t.Helper()
	c, err := f.store.CreateDNSCredential(context.Background(), f.org, name, "cloudflare", map[string]string{"CF_DNS_API_TOKEN": "tok-" + name})
	if err != nil {
		t.Fatal(err)
	}
	return c.ID
}

// issuedFor returns a self-signed EC certificate valid from now for 90 days.
//
//nolint:unused // shared test helper; used by Task 10's certstore tests, not this package's own.
func issuedFor(t *testing.T, names []string, now time.Time) *signer.Issued {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	return &signer.Issued{LeafDER: der, ChainDER: [][]byte{der}, PrivateKeyPKCS8: pk, NotBefore: tpl.NotBefore, NotAfter: tpl.NotAfter, Serial: "01"}
}
