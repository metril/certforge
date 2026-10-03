package localca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/signer"
)

func TestIssueVerifies(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(signer.EC256)
	mat, _, err := Generate(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	caID := uuid.New()

	t.Run("with base url", func(t *testing.T) {
		s := New(mat, cfg, noopRecorder{}, Opts{CAID: caID, BaseURL: "https://ca.example.com", Now: func() time.Time { return now }})
		issued, err := s.Issue(context.Background(), signer.IssueRequest{
			Names:   []string{"leaf.example.com", "10.0.0.5"},
			KeyType: signer.EC256,
		})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(issued.LeafDER)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.Subject.CommonName != "leaf.example.com" {
			t.Fatalf("cn = %q", leaf.Subject.CommonName)
		}
		if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
			t.Fatalf("ip sans = %v", leaf.IPAddresses)
		}
		wantCDP := fmt.Sprintf("https://ca.example.com/crl/%s/%s.crl", caID, mat.Issuing.SerialNumber.Text(16))
		if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != wantCDP {
			t.Fatalf("cdp = %v, want [%s]", leaf.CRLDistributionPoints, wantCDP)
		}
		wantEKU := map[x509.ExtKeyUsage]bool{x509.ExtKeyUsageServerAuth: true, x509.ExtKeyUsageClientAuth: true}
		if len(leaf.ExtKeyUsage) != len(wantEKU) {
			t.Fatalf("eku = %v", leaf.ExtKeyUsage)
		}
		for _, eku := range leaf.ExtKeyUsage {
			if !wantEKU[eku] {
				t.Fatalf("unexpected eku %v", eku)
			}
		}
		if len(issued.ChainDER) != 1 {
			t.Fatalf("chain = %d entries, want 1 (issuing only)", len(issued.ChainDER))
		}

		roots := x509.NewCertPool()
		roots.AddCert(mat.Root)
		inters := x509.NewCertPool()
		for _, c := range issued.ChainDER {
			cc, err := x509.ParseCertificate(c)
			if err != nil {
				t.Fatal(err)
			}
			inters.AddCert(cc)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatalf("leaf does not verify: %v", err)
		}
	})

	t.Run("without base url", func(t *testing.T) {
		s := New(mat, cfg, noopRecorder{}, Opts{CAID: caID, Now: func() time.Time { return now }})
		issued, err := s.Issue(context.Background(), signer.IssueRequest{Names: []string{"nobase.example.com"}, KeyType: signer.EC256})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(issued.LeafDER)
		if err != nil {
			t.Fatal(err)
		}
		if len(leaf.CRLDistributionPoints) != 0 {
			t.Fatalf("cdp present without a base url: %v", leaf.CRLDistributionPoints)
		}
	})
}

func TestLeafCappedByIssuer(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(signer.EC256)
	cfg.IssuingValidityYears = 1
	cfg.MaxLeafDays = 825 // longer than the issuing cert's own remaining life
	mat, _, err := Generate(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	s := New(mat, cfg, noopRecorder{}, Opts{CAID: uuid.New(), Now: func() time.Time { return now }})

	issued, err := s.Issue(context.Background(), signer.IssueRequest{Names: []string{"capped.example.com"}, KeyType: signer.EC256})
	if err != nil {
		t.Fatal(err)
	}
	if !issued.NotAfter.Equal(mat.Issuing.NotAfter) {
		t.Fatalf("leaf NotAfter = %v, want capped to issuer NotAfter %v", issued.NotAfter, mat.Issuing.NotAfter)
	}

	cfg2 := cfg
	cfg2.MaxLeafDays = 30
	mat2, _, err := Generate(cfg2, now)
	if err != nil {
		t.Fatal(err)
	}
	s2 := New(mat2, cfg2, noopRecorder{}, Opts{CAID: uuid.New(), Now: func() time.Time { return now }})
	issued2, err := s2.Issue(context.Background(), signer.IssueRequest{Names: []string{"short.example.com"}, KeyType: signer.EC256})
	if err != nil {
		t.Fatal(err)
	}
	want := now.Add(30 * 24 * time.Hour)
	if !issued2.NotAfter.Equal(want) {
		t.Fatalf("leaf NotAfter = %v, want %v (uncapped by issuer)", issued2.NotAfter, want)
	}
}

// TestIssueRefusesNearlyExpiredIssuer: an issuing certificate that has
// expired, or has under the 24 h floor left, must not sign a leaf.
func TestIssueRefusesNearlyExpiredIssuer(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(signer.EC256)
	mat, _, err := Generate(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	req := signer.IssueRequest{Names: []string{"late.example.com"}, KeyType: signer.EC256}
	for name, at := range map[string]time.Time{
		"expired":      mat.Issuing.NotAfter.Add(time.Hour),
		"inside floor": mat.Issuing.NotAfter.Add(-time.Hour),
	} {
		at := at
		s := New(mat, cfg, noopRecorder{}, Opts{CAID: uuid.New(), Now: func() time.Time { return at }})
		if _, err := s.Issue(context.Background(), req); !errors.Is(err, ErrIssuerExpiring) {
			t.Errorf("%s: err = %v, want ErrIssuerExpiring", name, err)
		}
	}
}

func TestRenewalInfoNotSupported(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(signer.EC256)
	mat, _, err := Generate(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	s := New(mat, cfg, noopRecorder{}, Opts{CAID: uuid.New(), Now: func() time.Time { return now }})
	if _, err := s.RenewalInfo(context.Background(), mat.Issuing); !errors.Is(err, signer.ErrNotSupported) {
		t.Fatalf("got %v, want signer.ErrNotSupported", err)
	}
}

func TestKind(t *testing.T) {
	s := New(Material{}, Config{}, noopRecorder{}, Opts{})
	if s.Kind() != "localca" {
		t.Fatalf("kind = %q, want localca", s.Kind())
	}
}
