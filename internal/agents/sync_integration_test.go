//go:build integration

package agents

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/signer"
)

// realCert returns a real, x509-parseable self-signed leaf and one chain
// certificate, plus a PKCS#8 EC key: the p12 renderer this task exercises
// parses its input rather than treating it as opaque bytes.
func realCert(t *testing.T, cn string, serial int64) ([]byte, [][]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: now, NotAfter: now.AddDate(0, 3, 0), DNSNames: []string{cn}}
	leafDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	chainTpl := &x509.Certificate{SerialNumber: big.NewInt(serial + 1000), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: now, NotAfter: now.AddDate(0, 3, 0)}
	chainDER, err := x509.CreateCertificate(rand.Reader, chainTpl, chainTpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return leafDER, [][]byte{chainDER}, pkcs8
}

// syncFixture is a minimal, direct-SQL fixture for Service.render/OnVersion/
// SweepDeployments/Bundle: it does not go through the api or issuance
// packages, only agents.Service itself plus raw inserts for the
// certificates/versions a grant needs.
type syncFixture struct {
	pool  *pgxpool.Pool
	q     *sqlcgen.Queries
	certs *certstore.Store
	box   crypto.Box
	svc   *Service
	org   uuid.UUID
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	pool, q := dbtest.New(t)
	box := cryptotest.PrefixBox{}
	certs := certstore.New(pool, box)
	org := dbtest.Org(t, pool)
	svc := &Service{Pool: pool, Q: q, CA: agentca.NewStore(pool, box), Certs: certs, Box: box, Log: slog.Default()}
	return &syncFixture{pool: pool, q: q, certs: certs, box: box, svc: svc, org: org}
}

// cert inserts a certificate row with no version and no current_version_id.
func (f *syncFixture) cert(t *testing.T, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO certificates (org_id, name, common_name) VALUES ($1, $2, $3) RETURNING id`,
		f.org, name, name+".example.test").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// version inserts a real, x509-parseable version of certID.
func (f *syncFixture) version(t *testing.T, certID uuid.UUID, serial int64, withKey bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	leafDER, chainDER, pkcs8 := realCert(t, "v.example.test", serial)
	iss := &signer.Issued{LeafDER: leafDER, ChainDER: chainDER, NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		Serial: fmt.Sprintf("%x", serial)}
	if withKey {
		iss.PrivateKeyPKCS8 = pkcs8
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.certs.Insert(ctx, tx, certID, iss, "ec256", certstore.InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return v.ID
}

// setCurrent makes versionID the certificate's current_version_id.
func (f *syncFixture) setCurrent(t *testing.T, certID, versionID uuid.UUID) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `UPDATE certificates SET current_version_id = $2, status = 'active' WHERE id = $1`,
		certID, versionID); err != nil {
		t.Fatal(err)
	}
}

// layout stores a layout; password, when non-empty, is sealed with f.box.
func (f *syncFixture) layout(t *testing.T, name string, files []delivery.OutputFile, password string, extraCertIDs []uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	b, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if password != "" {
		if sealed, err = f.box.Seal(ctx, []byte(password)); err != nil {
			t.Fatal(err)
		}
	}
	if extraCertIDs == nil {
		extraCertIDs = []uuid.UUID{}
	}
	l, err := f.q.CreateLayout(ctx, sqlcgen.CreateLayoutParams{OrgID: f.org, Name: name, Files: b, Password: sealed, ExtraCertIds: extraCertIDs})
	if err != nil {
		t.Fatal(err)
	}
	return l.ID
}

// client creates a pending client.
func (f *syncFixture) client(t *testing.T, name string) sqlcgen.Client {
	t.Helper()
	e, err := f.svc.CreateClient(context.Background(), f.org, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e.Client
}

func (f *syncFixture) desiredRevision(t *testing.T, clientID uuid.UUID) int64 {
	t.Helper()
	var rev int64
	if err := f.pool.QueryRow(context.Background(), `SELECT desired_revision FROM clients WHERE id = $1`, clientID).Scan(&rev); err != nil {
		t.Fatal(err)
	}
	return rev
}

func (f *syncFixture) expected(t *testing.T, grantID uuid.UUID) []byte {
	t.Helper()
	var b []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT expected FROM deployments WHERE grant_id = $1`, grantID).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

// expectedDigest returns a grant's single expected file's sha256; it fails
// the test if the deployment does not have exactly one expected file.
func (f *syncFixture) expectedDigest(t *testing.T, grantID uuid.UUID) string {
	t.Helper()
	var specs []agentproto.FileSpec
	if err := json.Unmarshal(f.expected(t, grantID), &specs); err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 {
		t.Fatalf("grant %s: expected 1 file, got %d: %+v", grantID, len(specs), specs)
	}
	return specs[0].SHA256
}

// Review Focus: a new version of a certificate used as another layout's
// extra certificate re-renders that layout's grants too (OnVersion), and
// the hourly sweep catches a skipped OnVersion the same way.
func TestExtraCertVersionRerenders(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	mainID := f.cert(t, "main")
	f.setCurrent(t, mainID, f.version(t, mainID, 1, true))

	extraID := f.cert(t, "extra")
	f.setCurrent(t, extraID, f.version(t, extraID, 2, true))

	layoutID := f.layout(t, "bundle",
		[]delivery.OutputFile{{Path: "/etc/ssl/extra.pem", Format: "pem", Parts: []string{"extra"}, Mode: "0644"}}, "", []uuid.UUID{extraID})

	c := f.client(t, "web-1")
	gid, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: mainID, Delivery: "pull", LayoutID: &layoutID})
	if err != nil {
		t.Fatal(err)
	}

	before := f.expected(t, gid)
	revBefore := f.desiredRevision(t, c.ID)

	extraVID2 := f.version(t, extraID, 3, true)
	f.setCurrent(t, extraID, extraVID2)
	f.svc.OnVersion(ctx, extraID, extraVID2)

	after := f.expected(t, gid)
	if bytes.Equal(before, after) {
		t.Fatal("expected digests unchanged after the extra certificate's new version")
	}
	if f.desiredRevision(t, c.ID) <= revBefore {
		t.Fatal("desired_revision not bumped by OnVersion")
	}

	// A version bump without calling OnVersion (simulating a process that
	// stopped before OnVersion ran) is caught by the sweep instead.
	revBeforeSweep := f.desiredRevision(t, c.ID)
	extraVID3 := f.version(t, extraID, 4, true)
	f.setCurrent(t, extraID, extraVID3)
	if err := f.svc.SweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	afterSweep := f.expected(t, gid)
	if bytes.Equal(after, afterSweep) {
		t.Fatal("sweep did not re-render after a skipped OnVersion")
	}
	if f.desiredRevision(t, c.ID) <= revBeforeSweep {
		t.Fatal("sweep did not bump desired_revision")
	}
}

// Review Focus: the agent bundle for a p12 layout decodes with the layout's
// own password, and its sha256 equals the assignment's expected digest.
func TestBundleCarriesKeystoreBytes(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	certID := f.cert(t, "web")
	f.setCurrent(t, certID, f.version(t, certID, 10, true))
	layoutID := f.layout(t, "p12", []delivery.OutputFile{{Path: "/etc/ssl/web.p12", Format: "p12", Mode: "0600"}}, "hunter2222", nil)

	c := f.client(t, "web-2")
	gid, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: certID, Delivery: "pull", LayoutID: &layoutID})
	if err != nil {
		t.Fatal(err)
	}

	cl, err := f.q.GetClientByID(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	asg, err := f.svc.Assignments(ctx, cl)
	if err != nil {
		t.Fatal(err)
	}
	if len(asg.Grants) != 1 || len(asg.Grants[0].Files) != 1 {
		t.Fatalf("assignments = %+v", asg)
	}
	wantDigest := asg.Grants[0].Files[0].SHA256

	b, err := f.svc.Bundle(ctx, cl, gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 1 {
		t.Fatalf("bundle files = %+v", b.Files)
	}
	if got := delivery.Digest(b.Files[0].Content); got != wantDigest {
		t.Fatalf("bundle digest %s != assignment digest %s", got, wantDigest)
	}
	if _, _, _, err := pkcs12.DecodeChain(b.Files[0].Content, "hunter2222"); err != nil {
		t.Fatalf("p12 does not decode with the layout password: %v", err)
	}
}

// Review Focus: the bundle renders extras from the deployment's own
// extra_version_ids (the versions actually last rendered), never the extra
// certificate's current version, so it keeps matching the assignment's
// expected digest even when a new version has landed but nothing has
// resynced yet.
func TestBundleUsesRenderedExtraVersions(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	mainID := f.cert(t, "main2")
	f.setCurrent(t, mainID, f.version(t, mainID, 20, true))

	extraID := f.cert(t, "extra2")
	f.setCurrent(t, extraID, f.version(t, extraID, 21, true))

	layoutID := f.layout(t, "bundle2",
		[]delivery.OutputFile{{Path: "/etc/ssl/extra.pem", Format: "pem", Parts: []string{"extra"}, Mode: "0644"}}, "", []uuid.UUID{extraID})

	c := f.client(t, "web-3")
	gid, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: mainID, Delivery: "pull", LayoutID: &layoutID})
	if err != nil {
		t.Fatal(err)
	}
	cl, err := f.q.GetClientByID(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.svc.Bundle(ctx, cl, gid)
	if err != nil {
		t.Fatal(err)
	}

	// The extra certificate gains a new version, but nothing resyncs it.
	f.setCurrent(t, extraID, f.version(t, extraID, 22, true))

	after, err := f.svc.Bundle(ctx, cl, gid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Files[0].Content, after.Files[0].Content) {
		t.Fatal("bundle content changed for an un-resynced extra certificate version")
	}
	asg, err := f.svc.Assignments(ctx, cl)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Digest(after.Files[0].Content) != asg.Grants[0].Files[0].SHA256 {
		t.Fatal("bundle digest no longer matches the assignment's expected digest")
	}
}

// Review Focus: render()'s per-batch material cache must key on (version
// id, withKey), not version id alone. A certificate used directly by one
// grant (its key rendered) and as another grant's extra certificate (keyless)
// can land in the same OnVersion/sweep batch when both grants share a
// client (GrantSources has no ORDER BY, so either row can be processed
// first): keying the cache on version id alone lets whichever request
// (with or without the key) runs first silently answer the other's
// request too, either failing the key-bearing grant with ErrNoKey or
// handing the extra a key-bearing copy it never asked for.
func TestBatchRenderKeyedByVersionAndKeyFlag(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	certA := f.cert(t, "shared-a")
	vidA1 := f.version(t, certA, 40, true)
	f.setCurrent(t, certA, vidA1)
	keyLayout := f.layout(t, "key-layout",
		[]delivery.OutputFile{{Path: "/etc/ssl/a-key.pem", Format: "pem", Parts: []string{"key"}, Mode: "0600"}}, "", nil)

	certB := f.cert(t, "shared-b")
	vidB := f.version(t, certB, 41, true)
	f.setCurrent(t, certB, vidB)
	extraLayout := f.layout(t, "extra-layout",
		[]delivery.OutputFile{{Path: "/etc/ssl/b-extra.pem", Format: "pem", Parts: []string{"extra"}, Mode: "0644"}}, "", []uuid.UUID{certA})

	c := f.client(t, "shared-client")
	// gB (extra references A) is created before gA (A's own key-bearing
	// grant): client_cert_grants has no secondary index GrantSources could
	// use besides the primary key, so a plain sequential scan for
	// `id = ANY($1)` returns rows in heap/insertion order for a table this
	// small, making gB's row (and its withKey=false load of A) the one
	// processed first.
	gB, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: certB, Delivery: "pull", LayoutID: &extraLayout})
	if err != nil {
		t.Fatal(err)
	}
	gA, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: certA, Delivery: "pull", LayoutID: &keyLayout})
	if err != nil {
		t.Fatal(err)
	}

	// A new version of A must re-render both grants, in one batch (OnVersion
	// unions LiveGrantIDsForCert(A) = {gA} and LiveGrantIDsForExtraCert(A) =
	// {gB}, and both share client c, so resyncGrants renders them together).
	vidA2 := f.version(t, certA, 42, true)
	f.setCurrent(t, certA, vidA2)
	f.svc.OnVersion(ctx, certA, vidA2)

	mA2, err := f.certs.Material(ctx, certA, vidA2, true)
	if err != nil {
		t.Fatal(err)
	}
	wantKeyFiles, err := render.PEM{}.Render(mA2, render.OutputOpts{Parts: []string{"key"}})
	if err != nil {
		t.Fatal(err)
	}
	wantKeyDigest := delivery.Digest(wantKeyFiles[0].Data)
	if got := f.expectedDigest(t, gA); got != wantKeyDigest {
		t.Fatalf("gA's key-bearing file did not re-render onto A's new version (ErrNoKey from a shared-key-flag cache entry?): got %s, want %s", got, wantKeyDigest)
	}

	mA2Keyless, err := f.certs.Material(ctx, certA, vidA2, false)
	if err != nil {
		t.Fatal(err)
	}
	wantExtraFiles, err := render.PEM{}.Render(render.Material{}, render.OutputOpts{Parts: []string{"extra"}, Extras: []render.Material{mA2Keyless}})
	if err != nil {
		t.Fatal(err)
	}
	wantExtraDigest := delivery.Digest(wantExtraFiles[0].Data)
	if got := f.expectedDigest(t, gB); got != wantExtraDigest {
		t.Fatalf("gB's extra part did not re-render onto A's new version: got %s, want %s", got, wantExtraDigest)
	}
}
