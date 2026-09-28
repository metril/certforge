package localca

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/metril/certforge/internal/signer"
)

func TestCRLParsesWithRevokedSerial(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mat, _, err := Generate(testCfg(signer.EC256), now)
	if err != nil {
		t.Fatal(err)
	}
	revokedSerial := big.NewInt(12345)
	crlDER, err := BuildCRL(mat.Issuing, mat.IssuingKey, []Revoked{
		{Serial: revokedSerial, RevokedAt: now, ReasonCode: 1},
	}, big.NewInt(7), now)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(mat.Issuing); err != nil {
		t.Fatalf("crl signature invalid: %v", err)
	}
	if crl.Number.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("crl number = %v, want 7", crl.Number)
	}
	if !crl.ThisUpdate.Equal(now) {
		t.Fatalf("thisUpdate = %v, want %v", crl.ThisUpdate, now)
	}
	wantNext := now.Add(7 * 24 * time.Hour)
	if !crl.NextUpdate.Equal(wantNext) {
		t.Fatalf("nextUpdate = %v, want %v", crl.NextUpdate, wantNext)
	}

	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(revokedSerial) == 0 {
			found = true
			if e.ReasonCode != 1 {
				t.Fatalf("reason code = %d, want 1", e.ReasonCode)
			}
		}
	}
	if !found {
		t.Fatal("revoked serial not present in crl")
	}
}

func TestRevokeRecordsAgainstIssuer(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(signer.EC256)
	mat, _, err := Generate(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingRecorder{}
	s := New(mat, cfg, rec, Opts{Now: func() time.Time { return now }})
	issued, err := s.Issue(context.Background(), signer.IssueRequest{Names: []string{"revoke-me.example.com"}, KeyType: signer.EC256})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(issued.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(context.Background(), leaf, 1); err != nil {
		t.Fatal(err)
	}
	if rec.serial != leaf.SerialNumber.Text(16) {
		t.Fatalf("recorded serial = %q, want %q", rec.serial, leaf.SerialNumber.Text(16))
	}
	if rec.issuerSerial != mat.Issuing.SerialNumber.Text(16) {
		t.Fatalf("recorded issuer serial = %q, want %q", rec.issuerSerial, mat.Issuing.SerialNumber.Text(16))
	}
	if rec.reason != 1 {
		t.Fatalf("recorded reason = %d, want 1", rec.reason)
	}
}

type recordingRecorder struct {
	serial, issuerSerial string
	reason               int
}

func (r *recordingRecorder) Revoke(ctx context.Context, serial, issuerSerial string, reason int, at time.Time) error {
	r.serial, r.issuerSerial, r.reason = serial, issuerSerial, reason
	return nil
}
