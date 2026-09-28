package vault

import (
	"context"
	"net"
	"net/http"
	"testing"
)

// TestPKISignParse covers request shaping (DNS names and IPs joined into
// separate comma-joined fields) and response parsing (the chain stays in
// the order Vault returned it, excluding the leaf).
func TestPKISignParse(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodPost, "/v1/pki/sign/server", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSR        string `json:"csr"`
			CommonName string `json:"common_name"`
			AltNames   string `json:"alt_names"`
			IPSans     string `json:"ip_sans"`
			Format     string `json:"format"`
			TTL        string `json:"ttl"`
		}
		if err := fv.LastBody(http.MethodPost, "/v1/pki/sign/server", &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.AltNames != "a.example,b.example" {
			t.Fatalf("alt_names = %q, want a.example,b.example", body.AltNames)
		}
		if body.IPSans != "10.0.0.1,10.0.0.2" {
			t.Fatalf("ip_sans = %q, want 10.0.0.1,10.0.0.2", body.IPSans)
		}
		if body.Format != "pem" {
			t.Fatalf("format = %q, want pem", body.Format)
		}
		if body.TTL != "24h" {
			t.Fatalf("ttl = %q, want 24h", body.TTL)
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"certificate":   "LEAF-PEM",
			"issuing_ca":    "ISSUER-PEM",
			"ca_chain":      []string{"ISSUER-PEM", "ROOT-PEM"},
			"serial_number": "39:dd:2e:aa",
		}})
	})

	c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
	resp, err := c.PKISign(context.Background(), "pki", "server", SignRequest{
		CSR:         "CSR-PEM",
		CommonName:  "a.example",
		DNSNames:    []string{"a.example", "b.example"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
		TTL:         "24h",
	})
	if err != nil {
		t.Fatalf("PKISign: %v", err)
	}
	if resp.Certificate != "LEAF-PEM" {
		t.Fatalf("Certificate = %q", resp.Certificate)
	}
	if len(resp.CAChain) != 2 || resp.CAChain[0] != "ISSUER-PEM" || resp.CAChain[1] != "ROOT-PEM" {
		t.Fatalf("CAChain = %v, want [ISSUER-PEM ROOT-PEM] in order", resp.CAChain)
	}
	if resp.SerialNumber != "39:dd:2e:aa" {
		t.Fatalf("SerialNumber = %q", resp.SerialNumber)
	}
}

// TestPKIRevokeSerialFormat: the serial is passed through to Vault exactly
// as given (colon-separated hex), never reformatted.
func TestPKIRevokeSerialFormat(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	const serial = "39:dd:2e:aa:11:22:33:44"
	fv.handle(http.MethodPost, "/v1/pki/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SerialNumber string `json:"serial_number"`
		}
		if err := fv.LastBody(http.MethodPost, "/v1/pki/revoke", &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.SerialNumber != serial {
			t.Fatalf("serial_number = %q, want %q", body.SerialNumber, serial)
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{}})
	})

	c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
	if err := c.PKIRevoke(context.Background(), "pki", serial); err != nil {
		t.Fatalf("PKIRevoke: %v", err)
	}
}

// TestPKIReadCA covers the plain CA-cert read.
func TestPKIReadCA(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodGet, "/v1/pki/cert/ca", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"certificate": "CA-PEM"}})
	})
	c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
	pem, err := c.PKIReadCA(context.Background(), "pki")
	if err != nil {
		t.Fatalf("PKIReadCA: %v", err)
	}
	if pem != "CA-PEM" {
		t.Fatalf("pem = %q, want CA-PEM", pem)
	}
}
