// Package vaultpki implements signer.Signer over a private CA backed by
// Vault's (or OpenBao's) PKI secrets engine.
package vaultpki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/vault"
)

// Code is this signer's CaType/meta.Entry code.
const Code = "vaultpki"

// Config is a vaultpki CA's signer config: the mount, role and optional TTL
// to sign leaves against (issuance's vaultPKIConfig, unsealed — vaultpki
// holds no secret material of its own, unlike localca).
type Config struct {
	Mount string
	Role  string
	TTL   string
}

// Signer implements signer.Signer over Vault's PKI secrets engine. It does
// not implement signer.DirectoryInfo (Vault PKI publishes no ACME
// directory's caaIdentities); RenewalInfo returns signer.ErrNotSupported
// (no ACME ARI to poll).
type Signer struct {
	client *vault.Client
	cfg    Config
}

// New builds a Signer that issues and revokes under cfg via client.
func New(client *vault.Client, cfg Config) *Signer {
	return &Signer{client: client, cfg: cfg}
}

func (s *Signer) Kind() string { return Code }

// Issue signs a leaf through Vault's PKI secrets engine: NewKeyAndCSR
// builds the key (honouring req.ReuseKeyPKCS8/req.KeyType) and PEM-encodes
// the CSR for PKISign. The returned leaf is cross-checked against the CSR's
// own public key — Vault signs whatever CSR it is handed, so a mismatched
// response would otherwise go unnoticed — and the chain comes from
// ca_chain, falling back to issuing_ca when Vault returned no chain.
func (s *Signer) Issue(ctx context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(req.Names) == 0 {
		return nil, errors.New("vaultpki: at least one name is required")
	}

	_, pkcs8, csrDER, err := signer.NewKeyAndCSR(req)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("vaultpki: parse csr: %w", err)
	}

	dns, ips := signer.SplitNames(req.Names)
	signReq := vault.SignRequest{
		CSR:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		CommonName: req.Names[0], DNSNames: dns, IPAddresses: ips,
	}
	if s.cfg.TTL != "" {
		signReq.TTL = s.cfg.TTL
	}
	resp, err := s.client.PKISign(ctx, s.cfg.Mount, s.cfg.Role, signReq)
	if err != nil {
		return nil, err
	}

	leaf, err := parsePEMCert(resp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("vaultpki: parse issued certificate: %w", err)
	}
	if !publicKeysEqual(leaf.PublicKey, csr.PublicKey) {
		return nil, errors.New("vaultpki: issued certificate's public key does not match the CSR")
	}

	chainDER, err := chainFromResponse(resp)
	if err != nil {
		return nil, err
	}

	return &signer.Issued{
		LeafDER: leaf.Raw, ChainDER: chainDER, PrivateKeyPKCS8: pkcs8,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		Serial: fmt.Sprintf("%x", leaf.SerialNumber),
	}, nil
}

// Revoke revokes cert through Vault's PKI secrets engine, by the serial
// Vault itself would have assigned it (colon-separated hex, derived from
// cert's own SerialNumber — PKIRevoke passes it through unreformatted).
func (s *Signer) Revoke(ctx context.Context, cert *x509.Certificate, _ int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.client.PKIRevoke(ctx, s.cfg.Mount, colonHex(cert.SerialNumber))
}

// RenewalInfo is not implemented: vaultpki has no ACME ARI to poll.
func (s *Signer) RenewalInfo(ctx context.Context, cert *x509.Certificate) (*signer.Window, error) {
	return nil, signer.ErrNotSupported
}

func parsePEMCert(s string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// chainFromResponse returns resp's issuing chain as DER, in the order Vault
// returned it: ca_chain when Vault sent one, otherwise the single
// issuing_ca certificate (Contract: "ChainDER from ca_chain, fallback
// issuing_ca").
func chainFromResponse(resp vault.SignResponse) ([][]byte, error) {
	pemChain := resp.CAChain
	if len(pemChain) == 0 && resp.IssuingCA != "" {
		pemChain = []string{resp.IssuingCA}
	}
	out := make([][]byte, 0, len(pemChain))
	for _, p := range pemChain {
		c, err := parsePEMCert(p)
		if err != nil {
			return nil, fmt.Errorf("vaultpki: parse chain certificate: %w", err)
		}
		out = append(out, c.Raw)
	}
	return out, nil
}

// colonHex formats sn the way Vault's PKI secrets engine reports and
// expects a certificate serial: lower-case hex bytes separated by colons
// (e.g. "1a:2b:3c").
func colonHex(sn *big.Int) string {
	b := sn.Bytes()
	parts := make([]string, len(b))
	for i, by := range b {
		parts[i] = fmt.Sprintf("%02x", by)
	}
	return strings.Join(parts, ":")
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	da, err1 := x509.MarshalPKIXPublicKey(a)
	db, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(da, db)
}
