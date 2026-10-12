//go:build integration

package issuance

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/signer/adcs"
	"github.com/metril/certforge/internal/signer/adcs/adcstest"
)

func adcsInput(fk *adcstest.Fake, name, pw string) CAInput {
	return CAInput{Name: name, Type: CATypeADCS, ADCSPassword: &pw, Config: map[string]any{
		"cepUrl": fk.CEPURL, "template": adcstest.Template, "username": adcstest.Username,
		"caBundlePem": fk.TLSCAPEM, "timeoutSeconds": 10,
	}}
}

func TestADCSCreateUpdateIssue(t *testing.T) {
	f := newFixture(t)
	f.store.SetADCSLoopback(func(context.Context) bool { return true })
	fk := adcstest.New(t)
	ctx := context.Background()

	ca, err := f.store.CreateCA(ctx, f.org, adcsInput(fk, "Corp AD CS", adcstest.Password))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ca.Type != CATypeADCS || !ca.Private() || ca.Config["templateOid"] != "1.3.6.1.4.1.311.21.8.1.2" ||
		ca.Config["cesUrl"] != fk.CESURL || ca.TrustBundlePEM == "" || ca.NotAfter == nil {
		t.Fatalf("ca = %+v", ca)
	}
	if _, ok := ca.Config["password"]; ok {
		t.Fatal("password leaked into config")
	}

	// The sealed password drives a working signer.
	sg, err := (&SignerFactory{Store: f.store}).New(ctx, ca)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := sg.Issue(ctx, signer.IssueRequest{Names: []string{"a.example.test"}, KeyType: signer.EC256})
	if err != nil || len(iss.ChainDER) != 1 {
		t.Fatalf("issue: %+v, %v", iss, err)
	}

	// Update with the sentinel keeps the stored password.
	un := challenge.Unchanged
	in := adcsInput(fk, "Corp AD CS 2", un)
	got, err := f.store.UpdateCA(ctx, f.org, ca.ID, in)
	if err != nil || got.Name != "Corp AD CS 2" {
		t.Fatalf("update sentinel: %+v, %v", got, err)
	}
	in.ADCSPassword = nil
	if _, err := f.store.UpdateCA(ctx, f.org, ca.ID, in); err != nil {
		t.Fatalf("update nil password: %v", err)
	}
	sg, _ = (&SignerFactory{Store: f.store}).New(ctx, got)
	if _, err := sg.Issue(ctx, signer.IssueRequest{Names: []string{"b.example.test"}, KeyType: signer.EC256}); err != nil {
		t.Fatalf("issue after sentinel update: %v", err)
	}

	// A saved password does not follow a changed endpoint, account or bundle.
	for name, mut := range map[string]func(map[string]any){
		"cepUrl":      func(m map[string]any) { m["cepUrl"] = fk.CEPURL + "?x=1" },
		"cesUrl":      func(m map[string]any) { m["cesUrl"] = "https://evil.example.test/ces" },
		"username":    func(m map[string]any) { m["username"] = "other" },
		"caBundlePem": func(m map[string]any) { m["caBundlePem"] = "" },
	} {
		for _, pw := range []*string{nil, &un} {
			chg := adcsInput(fk, "Corp AD CS 2", un)
			chg.ADCSPassword = pw
			mut(chg.Config)
			var cve *ValidationError
			if _, err := f.store.UpdateCA(ctx, f.org, ca.ID, chg); !errors.As(err, &cve) || cve.Field != "config.password" {
				t.Fatalf("%s changed with kept password: err = %v", name, err)
			}
		}
	}

	// A new wrong password is checked against the policy service.
	bad := "wrong"
	in.ADCSPassword = &bad
	var ve *ValidationError
	if _, err := f.store.UpdateCA(ctx, f.org, ca.ID, in); !errors.As(err, &ve) {
		t.Fatalf("wrong password: err = %v", err)
	}

	// Revocation is manual.
	if _, err := f.store.revokeSigner(ctx, f.store.q, mustRow(t, f, ca.ID), nil, nil); !errors.As(err, &ve) {
		t.Fatalf("revokeSigner: err = %v", err)
	}
}

func TestADCSCreateRejects(t *testing.T) {
	f := newFixture(t)
	f.store.SetADCSLoopback(func(context.Context) bool { return true })
	fk := adcstest.New(t)
	ctx := context.Background()
	var ve *ValidationError

	in := adcsInput(fk, "x", "wrong")
	if _, err := f.store.CreateCA(ctx, f.org, in); !errors.As(err, &ve) || ve.Field != "config.username" {
		t.Fatalf("bad password: %v", err)
	}
	in = adcsInput(fk, "x", adcstest.Password)
	in.Config["template"] = "Nope"
	if _, err := f.store.CreateCA(ctx, f.org, in); !errors.As(err, &ve) || ve.Field != "config.template" {
		t.Fatalf("unknown template: %v", err)
	}
	fk.EnrollmentFlags.Store(adcs.FlagPendAllRequests)
	if _, err := f.store.CreateCA(ctx, f.org, adcsInput(fk, "x", adcstest.Password)); !errors.As(err, &ve) || ve.Field != "config.template" {
		t.Fatalf("approval template: %v", err)
	}
	fk.EnrollmentFlags.Store(0)
	in = adcsInput(fk, "x", adcstest.Password)
	in.ADCSPassword = nil
	if _, err := f.store.CreateCA(ctx, f.org, in); !errors.As(err, &ve) || ve.Field != "config.password" {
		t.Fatalf("missing password: %v", err)
	}
	un := challenge.Unchanged
	in.ADCSPassword = &un
	if _, err := f.store.CreateCA(ctx, f.org, in); !errors.As(err, &ve) || ve.Field != "config.password" {
		t.Fatalf("sentinel on create: %v", err)
	}
	// Loopback is refused unless the policy allows it.
	f.store.SetADCSLoopback(nil)
	if _, err := f.store.CreateCA(ctx, f.org, adcsInput(fk, "x", adcstest.Password)); !errors.As(err, &ve) {
		t.Fatalf("loopback: %v", err)
	}
}

func mustRow(t *testing.T, f *fixture, id uuid.UUID) sqlcgen.Ca {
	t.Helper()
	row, err := f.store.q.GetCA(context.Background(), sqlcgen.GetCAParams{ID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// TestADCSUpdateKeepsConcurrentRewrap: a secret_cfg rewritten (as a rewrap
// does) between updateADCSCA's unlocked read and its lock must survive an
// update that keeps the password.
func TestADCSUpdateKeepsConcurrentRewrap(t *testing.T) {
	f := newFixture(t)
	f.store.SetADCSLoopback(func(context.Context) bool { return true })
	fk := adcstest.New(t)
	ctx := context.Background()
	ca, err := f.store.CreateCA(ctx, f.org, adcsInput(fk, "Race", adcstest.Password))
	if err != nil {
		t.Fatal(err)
	}
	rewrapped := []byte("rewrapped-blob")
	adcsUpdateHook = func() {
		if _, err := f.pool.Exec(ctx, `UPDATE cas SET secret_cfg = $2 WHERE id = $1`, ca.ID, rewrapped); err != nil {
			t.Error(err)
		}
	}
	defer func() { adcsUpdateHook = nil }()
	un := challenge.Unchanged
	if _, err := f.store.UpdateCA(ctx, f.org, ca.ID, adcsInput(fk, "Race 2", un)); err != nil {
		t.Fatal(err)
	}
	if got := mustRow(t, f, ca.ID).SecretCfg; string(got) != string(rewrapped) {
		t.Fatalf("secret_cfg = %q, want the concurrently rewrapped blob", got)
	}
}
