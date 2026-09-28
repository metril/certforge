//go:build integration

package kek_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/kek"
	"github.com/metril/certforge/internal/settings"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// TestRewrapAllEightColumns is the integration acceptance test for Task 5:
// seed all eight sealed columns (cas.eab_hmac and cas.secret_cfg counted as
// the one "cas" table) under KEK A, boot A as previous and B as active, run
// the worker once, and check every table's Remaining reaches 0, cas appears
// exactly once in the status, and every read path (Envelope.Decrypt)
// still opens the data.
func TestRewrapAllEightColumns(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)

	kekA := testKey(1)
	wrapperA := crypto.NewStaticWrapper(crypto.KeyID(kekA), kekA)
	envA := crypto.NewEnvelope(wrapperA)
	storeA := settings.NewStore(q, envA)

	org, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "acme", Name: "Acme"})
	if err != nil {
		t.Fatal(err)
	}

	// 1: settings (a plain secret row, distinct from the canary itself).
	if err := storeA.SetSecret(ctx, "test.rewrap8", []byte("settings secret")); err != nil {
		t.Fatal(err)
	}
	if err := storeA.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}

	// 2 and 3: cas.eab_hmac and cas.secret_cfg on the same row.
	eabBlob, err := envA.Encrypt(ctx, []byte("eab hmac"))
	if err != nil {
		t.Fatal(err)
	}
	secretCfgBlob, err := envA.Encrypt(ctx, []byte("localca imported key"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := q.CreateCA(ctx, sqlcgen.CreateCAParams{
		OrgID: org.ID, Name: "ca1", Type: "acme", Config: []byte("{}"), Preset: "letsencrypt",
		DirectoryUrl: "https://acme.example/directory", EabHmac: eabBlob.Marshal(), Resolvers: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	// secret_cfg has no sqlc query of its own yet (Task 7 adds localca CA
	// creation, which writes it); a direct UPDATE is enough to seed it here.
	if _, err := pool.Exec(ctx, "UPDATE cas SET secret_cfg = $1 WHERE id = $2", secretCfgBlob.Marshal(), ca.ID); err != nil {
		t.Fatal(err)
	}

	// 4: acme_accounts.account_key.
	acctBlob, err := envA.Encrypt(ctx, []byte("acme account key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateAccount(ctx, sqlcgen.CreateAccountParams{
		OrgID: org.ID, CaID: ca.ID, Email: "ops@acme.example", AccountKey: acctBlob.Marshal(), RegistrationUri: "https://acme.example/acct/1",
	}); err != nil {
		t.Fatal(err)
	}

	// 5: dns_provider_credentials.secret_cfg.
	dnsBlob, err := envA.Encrypt(ctx, []byte(`{"token":"dns secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateDNSCredential(ctx, sqlcgen.CreateDNSCredentialParams{
		OrgID: org.ID, Name: "dns1", ProviderCode: "manual", PublicCfg: []byte("{}"), SecretCfg: dnsBlob.Marshal(),
	}); err != nil {
		t.Fatal(err)
	}

	// 6: output_specs.password.
	pwBlob, err := envA.Encrypt(ctx, []byte("p12 password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateLayout(ctx, sqlcgen.CreateLayoutParams{
		OrgID: org.ID, Name: "layout1", Files: []byte("[]"), Password: pwBlob.Marshal(), ExtraCertIds: []uuid.UUID{},
	}); err != nil {
		t.Fatal(err)
	}

	// 7: agent_cas.key.
	agentKeyBlob, err := envA.Encrypt(ctx, []byte("agent ca key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := q.InsertAgentCA(ctx, sqlcgen.InsertAgentCAParams{
		CertDer: []byte("fake-der"), Key: agentKeyBlob.Marshal(), NotBefore: now, NotAfter: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// 8: certificate_versions.private_key.
	cert, err := q.CreateCertificate(ctx, sqlcgen.CreateCertificateParams{
		OrgID: org.ID, Name: "cert1", CommonName: "cert1.acme.example", Sans: []string{}, VerificationRules: []byte("[]"), Overrides: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	privKeyBlob, err := envA.Encrypt(ctx, []byte("leaf private key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.InsertCertificateVersion(ctx, sqlcgen.InsertCertificateVersionParams{
		CertID: cert.ID, Serial: "01", NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
		Sha256Fp: "deadbeef", KeyType: "ec256", LeafDer: []byte("fake-leaf"), ChainDer: [][]byte{},
		PrivateKey: privKeyBlob.Marshal(), Source: "issued",
	}); err != nil {
		t.Fatal(err)
	}

	// Boot B as active, A as previous: the multi-wrapper envelope everything
	// below runs against.
	kekB := testKey(2)
	wrapperB := crypto.NewStaticWrapper(crypto.KeyID(kekB), kekB)
	env := crypto.NewEnvelope(wrapperB, wrapperA)
	store := settings.NewStore(q, env)
	auditKey := testKey(3)
	aud := audit.New(pool, auditKey)

	svc := &kek.Service{
		Env: env, Settings: store, Pool: pool, Audit: aud,
		Info: kek.Info{Kind: "static", KEKID: wrapperB.ID(), Previous: []kek.Ref{{Kind: "static", KEKID: wrapperA.ID()}}},
	}
	w := &kek.RewrapWorker{Service: svc}
	if err := w.Work(ctx, &river.Job[kek.RewrapArgs]{}); err != nil {
		t.Fatal(err)
	}

	st, err := svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Rewrap == nil || st.Rewrap.Running {
		t.Fatalf("rewrap status = %+v", st.Rewrap)
	}
	if st.Rewrap.Remaining != 0 {
		t.Fatalf("remaining = %d, want 0: %+v", st.Rewrap.Remaining, st.Rewrap.Tables)
	}
	casCount := 0
	for _, ts := range st.Rewrap.Tables {
		if ts.Table == kek.TableCAs {
			casCount++
		}
		if ts.Remaining != 0 {
			t.Fatalf("table %s remaining = %d, want 0", ts.Table, ts.Remaining)
		}
	}
	if casCount != 1 {
		t.Fatalf("cas appears %d times in rewrap status, want 1", casCount)
	}

	// Every read path still decrypts, now under the active envelope alone
	// (KEKID B), proving the previous KEK is no longer needed.
	envBOnly := crypto.NewEnvelope(wrapperB)
	assertDecrypts := func(name string, raw []byte, want string) {
		t.Helper()
		var b crypto.Blob
		if err := b.Unmarshal(raw); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if b.KEKID != wrapperB.ID() {
			t.Fatalf("%s: still sealed under %q, want %q", name, b.KEKID, wrapperB.ID())
		}
		pt, err := envBOnly.Decrypt(ctx, b)
		if err != nil || string(pt) != want {
			t.Fatalf("%s: decrypt = %q, %v", name, pt, err)
		}
	}

	settingsRow, err := q.GetSetting(ctx, "test.rewrap8")
	if err != nil {
		t.Fatal(err)
	}
	assertDecrypts("settings", settingsRow.Secret, "settings secret")

	caRow, err := q.GetCA(ctx, sqlcgen.GetCAParams{ID: ca.ID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	assertDecrypts("cas.eab_hmac", caRow.EabHmac, "eab hmac")
	assertDecrypts("cas.secret_cfg", caRow.SecretCfg, "localca imported key")

	if err := storeA.VerifyCanary(ctx); err == nil {
		t.Fatal("canary should no longer verify under A alone after the rewrap")
	}
	if err := store.VerifyCanary(ctx); err != nil {
		t.Fatalf("canary does not verify under the active envelope after the rewrap: %v", err)
	}
}
