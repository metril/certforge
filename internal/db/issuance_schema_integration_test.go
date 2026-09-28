//go:build integration

package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func TestIssuanceSchema(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)

	ca, err := q.CreateCA(ctx, sqlcgen.CreateCAParams{OrgID: org, Name: "LE", Type: "acme", Config: []byte(`{}`), Preset: "letsencrypt",
		DirectoryUrl: "https://acme-v02.api.letsencrypt.org/directory", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateCA(ctx, sqlcgen.CreateCAParams{OrgID: org, Name: "LE", Type: "acme", Config: []byte(`{}`), Preset: "letsencrypt", DirectoryUrl: "x", Resolvers: []string{}}); err == nil {
		t.Fatal("duplicate CA name accepted")
	}
	caID := ca.ID
	over := []byte(`{"caId":"` + caID.String() + `"}`)
	cert, err := q.CreateCertificate(ctx, sqlcgen.CreateCertificateParams{OrgID: org, Name: "web", CommonName: "a.example.test",
		Sans: []string{}, VerificationRules: []byte(`[]`), Overrides: over})
	if err != nil {
		t.Fatal(err)
	}
	if cert.NextRenewAt == nil || cert.Status != "pending" || cert.CurrentVersionID != nil {
		t.Fatalf("new cert = %+v", cert)
	}
	if n, err := q.CountCAUsers(ctx, caID); err != nil || n != 1 {
		t.Fatalf("CountCAUsers = %d, %v", n, err)
	}
	ids, err := q.ListDueCertificateIDs(ctx, 10)
	if err != nil || len(ids) != 1 || ids[0] != cert.ID {
		t.Fatalf("due = %v %v", ids, err)
	}
	att, err := q.CreateAttempt(ctx, cert.ID)
	if err != nil || att.Outcome != "running" {
		t.Fatalf("attempt = %+v %v", att, err)
	}
	if ok, err := q.ManualAllConfirmed(ctx, att.ID); err != nil || ok {
		t.Fatalf("no records must not count as confirmed: %v %v", ok, err)
	}
	if err := q.InsertManualPending(ctx, sqlcgen.InsertManualPendingParams{AttemptID: att.ID, CertID: cert.ID, Domain: "a.example.test",
		Fqdn: "_acme-challenge.a.example.test", Value: "v", Ttl: 120, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if n, _ := q.ConfirmManualPending(ctx, cert.ID); n != 1 {
		t.Fatalf("confirmed %d", n)
	}
	if ok, _ := q.ManualAllConfirmed(ctx, att.ID); !ok {
		t.Fatal("confirmed records not seen")
	}
	if _, err := q.GetCertificate(ctx, sqlcgen.GetCertificateParams{ID: cert.ID, OrgID: uuid.New()}); err == nil {
		t.Fatal("certificate visible from another org")
	}
}
