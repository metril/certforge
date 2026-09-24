//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var (
	dbURL     = env("CF_E2E_DATABASE_URL", "postgres://certforge:certforge@localhost:55432/certforge?sslmode=disable")
	pebbleDir = env("CF_E2E_PEBBLE_DIR", "https://localhost:14000/dir")
	pebbleMgt = env("CF_E2E_PEBBLE_MGMT", "https://localhost:15000")
	challMgt  = env("CF_E2E_CHALLTESTSRV", "http://localhost:8055")
	dnsAddr   = env("CF_E2E_DNS", "127.0.0.1:8053")
)

// freshDatabase creates an empty database next to the compose one, so the
// running server's scheduler never sees this test's certificates.
func freshDatabase(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	admin, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect %s: %v", dbURL, err)
	}
	defer admin.Close(ctx)
	name := "e2e_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func waitFor[T any](ctx context.Context, t *testing.T, what string, poll func() (T, bool)) T {
	t.Helper()
	for {
		v, done := poll()
		if done {
			return v
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s: last %+v", what, v)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func fetchCert(ctx context.Context, t *testing.T, hc *http.Client, u string) *x509.Certificate {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s: no PEM", u)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestIssuanceAgainstPebble runs the issuance engine in-process against the
// Pebble and challtestsrv services of deploy/compose.test.yaml (make e2e).
func TestIssuanceAgainstPebble(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool := freshDatabase(ctx, t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var org uuid.UUID
	slug := "e2e-" + uuid.NewString()[:8]
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug, name) VALUES ($1, $1) RETURNING id`, slug).Scan(&org); err != nil {
		t.Fatal(err)
	}

	box := cryptotest.PrefixBox{} // e2e exercises ACME, not key wrapping
	store := issuance.NewStore(pool, box, nil)
	certs := certstore.New(pool, box)
	rc, err := issuance.NewRiver(pool, issuance.NewIssueWorker(store, certs), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = rc.StopAndCancel(sctx) // never block on a stuck job after a failure
	}()
	svc := issuance.NewService(store, certs, rc)

	trust, err := os.ReadFile("testdata/pebble.minica.pem")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := store.CreateCA(ctx, org, issuance.CAInput{Name: "Pebble", Preset: "custom", DirectoryURL: pebbleDir,
		TrustBundlePEM: string(trust), Resolvers: []string{dnsAddr}})
	if err != nil {
		t.Fatal(err)
	}
	acct, err := svc.RegisterAccount(ctx, org, ca.ID, "e2e@example.test")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := store.CreateDNSCredential(ctx, org, "challtestsrv", "e2e-challtestsrv", map[string]string{"CHALLTESTSRV_URL": challMgt})
	if err != nil {
		t.Fatal(err)
	}
	kt := signer.EC256
	if err := store.PutOrgDefaults(ctx, org, issuance.Defaults{CAID: &ca.ID, AccountID: &acct.ID, KeyType: &kt}); err != nil {
		t.Fatal(err)
	}
	cert, err := svc.CreateCertificate(ctx, org, issuance.CertInput{Name: "e2e", CommonName: "example.test",
		SANs:  []string{"*.example.test"},
		Rules: []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &cred.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	get := func() issuance.Certificate {
		c, err := store.GetCertificate(ctx, org, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// 1. Issued and active.
	c := waitFor(ctx, t, "active", func() (issuance.Certificate, bool) {
		c := get()
		return c, c.Status == issuance.StatusActive || c.FailureCount > 0
	})
	if c.Status != issuance.StatusActive {
		as, _ := store.ListAttempts(ctx, org, cert.ID, 1)
		t.Fatalf("issuance failed: %s\n%s", c.LastError, as[0].Log)
	}

	// 2. Chain verifies against Pebble's root and intermediate.
	m, err := certs.Material(ctx, c.ID, *c.CurrentVersionID, true)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(m.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(trust)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	inter := fetchCert(ctx, t, hc, pebbleMgt+"/intermediates/0")
	root := fetchCert(ctx, t, hc, pebbleMgt+"/roots/0")
	if len(m.ChainDER) == 0 || !slices.Equal(m.ChainDER[0], inter.Raw) {
		t.Fatal("stored chain does not start with Pebble intermediate 0")
	}
	rp, ip := x509.NewCertPool(), x509.NewCertPool()
	rp.AddCert(root)
	ip.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "foo.example.test", Roots: rp, Intermediates: ip}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}

	// 3. SANs.
	sans := slices.Clone(leaf.DNSNames)
	slices.Sort(sans)
	if !slices.Equal(sans, []string{"*.example.test", "example.test"}) {
		t.Fatalf("SANs = %v", sans)
	}

	// 4. Key type EC P-256 and the stored key matches the leaf.
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("key = %T", leaf.PublicKey)
	}
	k, err := x509.ParsePKCS8PrivateKey(m.PrivateKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	kpriv, ok := k.(*ecdsa.PrivateKey)
	if !ok || !kpriv.PublicKey.Equal(pub) {
		t.Fatal("stored private key does not match leaf")
	}

	// 5. Forced renewal creates a second version.
	if _, err := svc.EnqueueIssue(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(ctx, t, "second version", func() (int, bool) {
		vs, _ := certs.List(ctx, c.ID)
		return len(vs), len(vs) == 2
	})

	// 6. Broken credential: failure recorded, backoff scheduled.
	if _, err := store.UpdateDNSCredential(ctx, org, cred.ID, "challtestsrv", map[string]string{"CHALLTESTSRV_URL": "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	waitFor(ctx, t, "renewal to be enqueued", func() (bool, bool) {
		ok, err := svc.EnqueueIssue(ctx, c.ID)
		return ok, err == nil && ok
	})
	c = waitFor(ctx, t, "failure", func() (issuance.Certificate, bool) {
		c := get()
		return c, c.FailureCount == 1
	})
	if c.LastError == "" || c.NextRenewAt == nil || c.NextRenewAt.Before(before.Add(4*time.Minute)) {
		t.Fatalf("backoff not scheduled: %+v", c)
	}
	if c.Status != issuance.StatusActive {
		t.Fatalf("a failed renewal must keep a valid cert active, got %s", c.Status)
	}
	as, _ := store.ListAttempts(ctx, org, c.ID, 1)
	if as[0].Outcome != issuance.OutcomeFailed {
		t.Fatalf("attempt = %+v", as[0])
	}
}
