//go:build integration

package kek_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
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
	acct, err := q.CreateAccount(ctx, sqlcgen.CreateAccountParams{
		OrgID: org.ID, CaID: ca.ID, Email: "ops@acme.example", AccountKey: acctBlob.Marshal(), RegistrationUri: "https://acme.example/acct/1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5: dns_provider_credentials.secret_cfg.
	dnsBlob, err := envA.Encrypt(ctx, []byte(`{"token":"dns secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	dnsCred, err := q.CreateDNSCredential(ctx, sqlcgen.CreateDNSCredentialParams{
		OrgID: org.ID, Name: "dns1", ProviderCode: "manual", PublicCfg: []byte("{}"), SecretCfg: dnsBlob.Marshal(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 6: output_specs.password.
	pwBlob, err := envA.Encrypt(ctx, []byte("p12 password"))
	if err != nil {
		t.Fatal(err)
	}
	layout, err := q.CreateLayout(ctx, sqlcgen.CreateLayoutParams{
		OrgID: org.ID, Name: "layout1", Files: []byte("[]"), Password: pwBlob.Marshal(), ExtraCertIds: []uuid.UUID{},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 7: agent_cas.key.
	agentKeyBlob, err := envA.Encrypt(ctx, []byte("agent ca key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	agentCA, err := q.InsertAgentCA(ctx, sqlcgen.InsertAgentCAParams{
		CertDer: []byte("fake-der"), Key: agentKeyBlob.Marshal(), NotBefore: now, NotAfter: now.Add(24 * time.Hour),
	})
	if err != nil {
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
	version, err := q.InsertCertificateVersion(ctx, sqlcgen.InsertCertificateVersionParams{
		CertID: cert.ID, Serial: "01", NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
		Sha256Fp: "deadbeef", KeyType: "ec256", LeafDer: []byte("fake-leaf"), ChainDer: [][]byte{},
		PrivateKey: privKeyBlob.Marshal(), Source: "issued",
	})
	if err != nil {
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
	// Expected Rewrapped per table: cas holds both eab_hmac and secret_cfg
	// (2), every other table holds exactly the one row seeded above (1).
	// This is what review batch 2's finding #2 asks for beyond Remaining==0
	// alone: Remaining reaching 0 via the same Page query the rewrap itself
	// used would pass silently even if that query were mis-wired to never
	// see a row in the first place (Rewrapped would then also read 0, which
	// this catches).
	wantRewrapped := map[kek.RewrapTable]int64{
		// crypto.canary is rewrapped by the dedicated canary-first step
		// (not by this table's own pass, which finds it already
		// active-sealed and skips it as a no-op); only test.rewrap8 counts
		// here.
		kek.TableSettings:               1,
		kek.TableCAs:                    2,
		kek.TableAcmeAccounts:           1,
		kek.TableDNSProviderCredentials: 1,
		kek.TableOutputSpecs:            1,
		kek.TableAgentCAs:               1,
		kek.TableCertificateVersions:    1,
	}
	casCount := 0
	for _, ts := range st.Rewrap.Tables {
		if ts.Table == kek.TableCAs {
			casCount++
		}
		if ts.Remaining != 0 {
			t.Fatalf("table %s remaining = %d, want 0", ts.Table, ts.Remaining)
		}
		if want := wantRewrapped[ts.Table]; ts.Rewrapped != want {
			t.Fatalf("table %s rewrapped = %d, want %d", ts.Table, ts.Rewrapped, want)
		}
	}
	if casCount != 1 {
		t.Fatalf("cas appears %d times in rewrap status, want 1", casCount)
	}

	// The stored crypto.rewrap row round-trips with the RewrapStatus
	// schema's camelCase keys (review batch 2 finding #3), not Go field
	// names: checked against the raw jsonb value, not just the RewrapStatus
	// Go value Status() already decoded above.
	rewrapRow, err := q.GetSetting(ctx, settings.RewrapKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"running"`, `"startedAt"`, `"finishedAt"`, `"activeKekId"`, `"previousKekIds"`,
		`"tables"`, `"remaining"`, `"error"`, `"table"`, `"scanned"`, `"rewrapped"`} {
		if !bytes.Contains(rewrapRow.Value, []byte(key)) {
			t.Fatalf("stored crypto.rewrap row missing key %s: %s", key, rewrapRow.Value)
		}
	}
	var stored kek.RewrapStatus
	if err := json.Unmarshal(rewrapRow.Value, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.ActiveKEKID != wrapperB.ID() || stored.Remaining != 0 || len(stored.Tables) != len(kek.Tables) {
		t.Fatalf("stored row does not round-trip: %+v", stored)
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

	acctRow, err := q.GetAccountByID(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertDecrypts("acme_accounts.account_key", acctRow.AccountKey, "acme account key")

	dnsRow, err := q.GetDNSCredential(ctx, sqlcgen.GetDNSCredentialParams{ID: dnsCred.ID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	assertDecrypts("dns_provider_credentials.secret_cfg", dnsRow.SecretCfg, `{"token":"dns secret"}`)

	layoutRow, err := q.GetLayout(ctx, sqlcgen.GetLayoutParams{ID: layout.ID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	assertDecrypts("output_specs.password", layoutRow.Password, "p12 password")

	agentCARow, err := q.GetAgentCA(ctx, agentCA.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertDecrypts("agent_cas.key", agentCARow.Key, "agent ca key")

	versionRow, err := q.GetCertificateVersion(ctx, sqlcgen.GetCertificateVersionParams{ID: version.ID, CertID: cert.ID})
	if err != nil {
		t.Fatal(err)
	}
	assertDecrypts("certificate_versions.private_key", versionRow.PrivateKey, "leaf private key")

	if err := storeA.VerifyCanary(ctx); err == nil {
		t.Fatal("canary should no longer verify under A alone after the rewrap")
	}
	if err := store.VerifyCanary(ctx); err != nil {
		t.Fatalf("canary does not verify under the active envelope after the rewrap: %v", err)
	}
}

// TestRewrapIncludesChannels covers Phase 6A Task 1 (Deviations R10):
// notification_channels.secret_cfg is appended to kek.Tables, so a channel
// secret sealed under KEK A is rewrapped to B along with everything else.
// notification_channels has no sqlc query of its own yet (Task 6 adds
// channel creation); a direct INSERT/UPDATE is enough to seed it here, the
// same way TestRewrapAllEightColumns seeds cas.secret_cfg.
func TestRewrapIncludesChannels(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)

	kekA := testKey(31)
	wrapperA := crypto.NewStaticWrapper(crypto.KeyID(kekA), kekA)
	envA := crypto.NewEnvelope(wrapperA)

	org, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "rewrap-channels", Name: "Rewrap Channels"})
	if err != nil {
		t.Fatal(err)
	}

	secretBlob, err := envA.Encrypt(ctx, []byte(`{"authHeader":"Bearer s3cret"}`))
	if err != nil {
		t.Fatal(err)
	}
	var channelID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO notification_channels (org_id, name, type, secret_cfg) VALUES ($1, 'c1', 'webhook', $2) RETURNING id`,
		org.ID, secretBlob.Marshal(),
	).Scan(&channelID); err != nil {
		t.Fatal(err)
	}

	kekB := testKey(32)
	wrapperB := crypto.NewStaticWrapper(crypto.KeyID(kekB), kekB)
	env := crypto.NewEnvelope(wrapperB, wrapperA)
	store := settings.NewStore(q, env)
	auditKey := testKey(33)
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
	if st.Rewrap == nil || st.Rewrap.Running || st.Rewrap.Remaining != 0 {
		t.Fatalf("rewrap status = %+v", st.Rewrap)
	}
	found := false
	for _, ts := range st.Rewrap.Tables {
		if ts.Table != kek.TableNotificationChannels {
			continue
		}
		found = true
		if ts.Rewrapped != 1 || ts.Remaining != 0 {
			t.Fatalf("notification_channels table status = %+v", ts)
		}
	}
	if !found {
		t.Fatal("notification_channels not present in rewrap status")
	}

	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT secret_cfg FROM notification_channels WHERE id = $1`, channelID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var b crypto.Blob
	if err := b.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	if b.KEKID != wrapperB.ID() {
		t.Fatalf("secret_cfg still sealed under %q, want active %q", b.KEKID, wrapperB.ID())
	}
	envBOnly := crypto.NewEnvelope(wrapperB)
	pt, err := envBOnly.Decrypt(ctx, b)
	if err != nil || string(pt) != `{"authHeader":"Bearer s3cret"}` {
		t.Fatalf("decrypt under active envelope = %q, %v", pt, err)
	}
}

// TestRewrapCASLosesRaceSafely covers final review finding 1:
// issuance.Store.UpdateCA (the ACME branch) now locks the cas row FOR
// UPDATE (LockCA) across its read of eab_hmac and its write of the same,
// kept-unchanged value, instead of a plain, unlocked GetCA — so a
// concurrent rewrap's CAS on that same row can never land between the read
// and the write and be silently clobbered by the stale (pre-rewrap) blob
// UpdateCA read earlier. The concurrent writer here is a minimal,
// single-row simulation of RewrapWorker's own CAS step (rewrapBlob's
// "sealed under a previous KEK" branch: decrypt under A, re-encrypt under
// B, conditional UPDATE) rather than a full kek.RewrapWorker.Work() run —
// Work() visits six other, empty tables before it ever reaches this row,
// which makes it consistently slower than UpdateCA's own one or two round
// trips and starves the race of any real window; this minimal version has
// comparable latency, giving the interleaving this fix closes a genuine
// chance to occur. Under real Postgres row locking the outcome is still
// deterministic regardless of which goroutine's transaction reaches the
// row first: the other blocks behind it until it commits — so the final
// eab_hmac must always end up sealed under the active KEK (B), never
// reverted to the previous one (A) the rewrap moved it off of. Twenty
// iterations, each racing a fresh CA row, to exercise both lock orders.
func TestRewrapCASLosesRaceSafely(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)

	kekA := testKey(21)
	wrapperA := crypto.NewStaticWrapper(crypto.KeyID(kekA), kekA)
	envA := crypto.NewEnvelope(wrapperA)

	kekB := testKey(22)
	wrapperB := crypto.NewStaticWrapper(crypto.KeyID(kekB), kekB)
	env := crypto.NewEnvelope(wrapperB, wrapperA)

	org, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "rewrap-race", Name: "Rewrap Race"})
	if err != nil {
		t.Fatal(err)
	}
	store := issuance.NewStore(pool, crypto.EnvelopeBox{Env: env}, nil)

	for i := 0; i < 20; i++ {
		eabBlob, err := envA.Encrypt(ctx, []byte("eab hmac"))
		if err != nil {
			t.Fatal(err)
		}
		ca, err := q.CreateCA(ctx, sqlcgen.CreateCAParams{
			OrgID: org.ID, Name: fmt.Sprintf("ca-race-%d", i), Type: "acme", Config: []byte("{}"), Preset: "letsencrypt",
			DirectoryUrl: "https://acme.example/directory", EabHmac: eabBlob.Marshal(), Resolvers: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}

		// start is a rendezvous (same pattern as internal/api's
		// TestGrantKeylessRace): both goroutines block on it and are
		// released by one close, so their transactions begin as close to
		// simultaneously as the Go scheduler allows.
		start := make(chan struct{})
		var wg sync.WaitGroup
		var updateErr, rewrapErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, updateErr = store.UpdateCA(ctx, org.ID, ca.ID, issuance.CAInput{
				Name: ca.Name, Preset: "letsencrypt", DirectoryURL: ca.DirectoryUrl, Resolvers: []string{},
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			row, err := q.GetCA(ctx, sqlcgen.GetCAParams{ID: ca.ID, OrgID: org.ID})
			if err != nil {
				rewrapErr = err
				return
			}
			var b crypto.Blob
			if err := b.Unmarshal(row.EabHmac); err != nil {
				rewrapErr = err
				return
			}
			if b.KEKID == wrapperB.ID() {
				return // already rewrapped by an earlier pass; nothing to do
			}
			pt, err := env.Decrypt(ctx, b)
			if err != nil {
				rewrapErr = err
				return
			}
			nb, err := env.Encrypt(ctx, pt)
			if err != nil {
				rewrapErr = err
				return
			}
			// The CAS itself: only applies if eab_hmac still equals what
			// was just read, exactly like Store.CAS (internal/kek/rewrap.go).
			_, rewrapErr = pool.Exec(ctx, `UPDATE cas SET eab_hmac = $1 WHERE id = $2 AND eab_hmac = $3`, nb.Marshal(), ca.ID, row.EabHmac)
		}()
		close(start)
		wg.Wait()

		if updateErr != nil {
			t.Fatalf("iteration %d: UpdateCA: %v", i, updateErr)
		}
		if rewrapErr != nil {
			t.Fatalf("iteration %d: rewrap: %v", i, rewrapErr)
		}

		row, err := q.GetCA(ctx, sqlcgen.GetCAParams{ID: ca.ID, OrgID: org.ID})
		if err != nil {
			t.Fatal(err)
		}
		var b crypto.Blob
		if err := b.Unmarshal(row.EabHmac); err != nil {
			t.Fatalf("iteration %d: eab_hmac unmarshal: %v", i, err)
		}
		if b.KEKID != wrapperB.ID() {
			t.Fatalf("iteration %d: eab_hmac sealed under %q, want active %q (the rewrap was lost)", i, b.KEKID, wrapperB.ID())
		}
		pt, err := env.Decrypt(ctx, b)
		if err != nil || string(pt) != "eab hmac" {
			t.Fatalf("iteration %d: eab_hmac decrypt = %q, %v", i, pt, err)
		}
	}
}
