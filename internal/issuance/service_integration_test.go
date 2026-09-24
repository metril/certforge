//go:build integration

package issuance

import (
	"context"
	"errors"
	"strings"
	"testing"

	legochallenge "github.com/go-acme/lego/v4/challenge"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/signer"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
)

type fakeRegistrar struct {
	gotEAB *acmesigner.EAB
	err    error
}

func (r *fakeRegistrar) Register(_ context.Context, email string, eab *acmesigner.EAB) (signer.AccountMaterial, error) {
	r.gotEAB = eab
	if r.err != nil {
		return signer.AccountMaterial{}, r.err
	}
	return signer.AccountMaterial{Email: email, KeyPKCS8: []byte("k"), RegistrationURI: "https://ca.test/acct/9"}, nil
}

type recDNS struct{ presented, cleaned []string }

func (r *recDNS) Present(d, _, _ string) error { r.presented = append(r.presented, d); return nil }
func (r *recDNS) CleanUp(d, _, _ string) error { r.cleaned = append(r.cleaned, d); return nil }

func newService(f *fixture) (*Service, *fakeInserter) {
	ins := &fakeInserter{seen: map[string]bool{}}
	return NewService(f.store, certstore.New(f.pool, cryptotest.PrefixBox{}), ins), ins
}

func TestRegisterAccountPassesEAB(t *testing.T) {
	f := newFixture(t)
	svc, _ := newService(f)
	hmac := "aG1hYw"
	ca, err := f.store.CreateCA(context.Background(), f.org, CAInput{Name: "GTS", Preset: "google", EABKid: "kid-1", EABHmac: &hmac})
	if err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistrar{}
	svc.NewRegistrar = func(CA) Registrar { return reg }
	a, err := svc.RegisterAccount(context.Background(), f.org, ca.ID, "ops@example.test")
	if err != nil || a.RegistrationURI != "https://ca.test/acct/9" || a.Status != "valid" {
		t.Fatalf("account = %+v err = %v", a, err)
	}
	if reg.gotEAB == nil || reg.gotEAB.KID != "kid-1" || reg.gotEAB.HMAC != hmac {
		t.Fatalf("eab = %+v", reg.gotEAB)
	}
	reg.err = &signer.Error{Type: "urn:ietf:params:acme:error:externalAccountRequired", Err: errors.New("eab required")}
	if _, err := svc.RegisterAccount(context.Background(), f.org, ca.ID, "other@example.test"); err == nil {
		t.Fatal("registration error swallowed")
	}
}

// TestRegisterAccountPropagatesNonNotFoundErrors: only a CA lookup that
// actually finds no such row in this org should become a 422
// *ValidationError; any other error from the lookup (here, a database error
// from a cancelled context) must come back unchanged so it isn't misreported
// as a bad caId and, e.g. mapped to a client-facing 422 instead of a 500.
func TestRegisterAccountPropagatesNonNotFoundErrors(t *testing.T) {
	f := newFixture(t)
	svc, _ := newService(f)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := svc.RegisterAccount(ctx, f.org, f.ca.ID, "ops@example.test")
	if err == nil {
		t.Fatal("want an error from a cancelled context")
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		t.Fatalf("cancelled context reported as %v", err)
	}
}

func TestCreateCertificateEnqueues(t *testing.T) {
	f := newFixture(t)
	svc, ins := newService(f)
	c, err := svc.CreateCertificate(context.Background(), f.org, CertInput{Name: "a", CommonName: "a.example.test"})
	if err != nil || len(ins.args) != 1 || ins.args[0].CertID != c.ID {
		t.Fatalf("args = %v err = %v", ins.args, err)
	}
	if ok, _ := svc.EnqueueIssue(context.Background(), c.ID); ok {
		t.Fatal("duplicate enqueue must report false")
	}
}

func TestTestDNSCredential(t *testing.T) {
	f := newFixture(t)
	svc, _ := newService(f)
	rec := &recDNS{}
	svc.BuildDNS = func(string, map[string]string) (legochallenge.Provider, error) { return rec, nil }
	fqdn, err := svc.TestDNSCredential(context.Background(), f.org, f.credential(t, "cf"), "example.test.")
	if err != nil || fqdn != "_acme-challenge._certforge-test.example.test" {
		t.Fatalf("fqdn = %q err = %v", fqdn, err)
	}
	if strings.Join(rec.presented, ",") != "_certforge-test.example.test" || len(rec.cleaned) != 1 {
		t.Fatalf("present=%v cleanup=%v", rec.presented, rec.cleaned)
	}
}

func TestNewRiverConfigIsValid(t *testing.T) {
	f := newFixture(t)
	w := NewIssueWorker(f.store, certstore.New(f.pool, cryptotest.PrefixBox{}))
	if _, err := NewRiver(f.pool, w, f.store, nil); err != nil {
		t.Fatal(err)
	}
}
