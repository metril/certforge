package vaultpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/vault"
)

func genCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, signerKey any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// selfSignedCA builds a throwaway CA certificate+key standing in for
// Vault's own PKI mount.
func selfSignedCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	return genCert(t, tmpl, tmpl, &key.PublicKey, key), key
}

func pemCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// signResponder is a fake Vault PKI sign/<role> handler: it signs whichever
// public key wantWrongKey selects (the CSR's own key normally, or an
// unrelated one to simulate Vault returning a mismatched certificate) over
// the request's CSR-derived names, and records the last decoded body for
// assertions.
type signResponder struct {
	t           *testing.T
	ca          *x509.Certificate
	caKey       *ecdsa.PrivateKey
	chain       []string // ca_chain to return; nil tests the issuing_ca fallback
	issuingCA   string
	wrongKeyPub any // non-nil: sign the leaf over this key instead of the CSR's
	lastBody    map[string]any
}

func (s *signResponder) handle(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.t.Fatal(err)
	}
	s.lastBody = body
	csrPEM, _ := body["csr"].(string)
	blk, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		s.t.Fatal(err)
	}

	pub := any(csr.PublicKey)
	if s.wrongKeyPub != nil {
		pub = s.wrongKeyPub
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: csr.Subject.CommonName},
		DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses,
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}
	leaf := genCert(s.t, tmpl, s.ca, pub, s.caKey)

	data := map[string]any{"certificate": pemCert(leaf), "serial_number": "2a"}
	if s.chain != nil {
		data["ca_chain"] = s.chain
	}
	if s.issuingCA != "" {
		data["issuing_ca"] = s.issuingCA
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func newTestClient(t *testing.T, url string) *vault.Client {
	t.Helper()
	c, err := vault.New(vault.Config{Addr: url, Auth: vault.TokenAuth{Token: "t0"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestVaultPKIIssueParse covers Issue's request shape and response parsing:
// alt_names/ip_sans are sent, ttl is sent only when configured, and the
// chain comes from ca_chain in the order Vault returned it.
func TestVaultPKIIssueParse(t *testing.T) {
	ca, caKey := selfSignedCA(t, "issuing")
	root, _ := selfSignedCA(t, "root")
	resp := &signResponder{t: t, ca: ca, caKey: caKey, chain: []string{pemCert(ca), pemCert(root)}}
	srv := httptest.NewServer(http.HandlerFunc(resp.handle))
	defer srv.Close()

	sg := New(newTestClient(t, srv.URL), Config{Mount: "pki", Role: "myrole", TTL: "48h"})
	issued, err := sg.Issue(context.Background(), signer.IssueRequest{
		Names: []string{"leaf.example.test", "10.0.0.5"}, KeyType: signer.EC256,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if resp.lastBody["ttl"] != "48h" {
		t.Fatalf("ttl = %v, want 48h", resp.lastBody["ttl"])
	}
	if resp.lastBody["common_name"] != "leaf.example.test" {
		t.Fatalf("common_name = %v", resp.lastBody["common_name"])
	}
	if resp.lastBody["ip_sans"] != "10.0.0.5" {
		t.Fatalf("ip_sans = %v", resp.lastBody["ip_sans"])
	}

	if len(issued.ChainDER) != 2 {
		t.Fatalf("chain len = %d, want 2", len(issued.ChainDER))
	}
	c0, err := x509.ParseCertificate(issued.ChainDER[0])
	if err != nil || c0.Subject.CommonName != "issuing" {
		t.Fatalf("chain[0] = %+v err %v, want issuing first", c0, err)
	}
	c1, err := x509.ParseCertificate(issued.ChainDER[1])
	if err != nil || c1.Subject.CommonName != "root" {
		t.Fatalf("chain[1] = %+v err %v, want root second", c1, err)
	}

	leaf, err := x509.ParseCertificate(issued.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("leaf ip sans = %v", leaf.IPAddresses)
	}

	// A signer with no configured TTL must not send one.
	sg2 := New(newTestClient(t, srv.URL), Config{Mount: "pki", Role: "myrole"})
	if _, err := sg2.Issue(context.Background(), signer.IssueRequest{Names: []string{"other.example.test"}, KeyType: signer.EC256}); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.lastBody["ttl"]; ok {
		t.Fatalf("ttl sent when not configured: %v", resp.lastBody["ttl"])
	}
}

// TestVaultPKIIssueFallsBackToIssuingCA covers the ca_chain-absent case:
// Issue falls back to the single issuing_ca certificate.
func TestVaultPKIIssueFallsBackToIssuingCA(t *testing.T) {
	ca, caKey := selfSignedCA(t, "issuing")
	resp := &signResponder{t: t, ca: ca, caKey: caKey, issuingCA: pemCert(ca)}
	srv := httptest.NewServer(http.HandlerFunc(resp.handle))
	defer srv.Close()

	sg := New(newTestClient(t, srv.URL), Config{Mount: "pki", Role: "myrole"})
	issued, err := sg.Issue(context.Background(), signer.IssueRequest{Names: []string{"leaf.example.test"}, KeyType: signer.EC256})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(issued.ChainDER) != 1 {
		t.Fatalf("chain len = %d, want 1 (issuing_ca fallback)", len(issued.ChainDER))
	}
}

// TestVaultPKIRejectsMismatchedKey covers the cross-check: a certificate
// Vault returns for a public key other than the CSR's own is rejected
// rather than silently accepted.
func TestVaultPKIRejectsMismatchedKey(t *testing.T) {
	ca, caKey := selfSignedCA(t, "issuing")
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resp := &signResponder{t: t, ca: ca, caKey: caKey, issuingCA: pemCert(ca), wrongKeyPub: &wrongKey.PublicKey}
	srv := httptest.NewServer(http.HandlerFunc(resp.handle))
	defer srv.Close()

	sg := New(newTestClient(t, srv.URL), Config{Mount: "pki", Role: "myrole"})
	_, err = sg.Issue(context.Background(), signer.IssueRequest{Names: []string{"leaf.example.test"}, KeyType: signer.EC256})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v, want a public key mismatch error", err)
	}
}

// TestVaultPKIRenewalInfoNotSupported covers RenewalInfo (no ACME ARI to poll).
func TestVaultPKIRenewalInfoNotSupported(t *testing.T) {
	sg := New(nil, Config{Mount: "pki", Role: "r"})
	if _, err := sg.RenewalInfo(context.Background(), &x509.Certificate{}); !errors.Is(err, signer.ErrNotSupported) {
		t.Fatalf("err = %v, want signer.ErrNotSupported", err)
	}
}
