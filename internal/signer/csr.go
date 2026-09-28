package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
)

// SplitNames splits names into DNS names and IP addresses, preserving
// order within each group. It is shared by NewKeyAndCSR and the CA
// implementations (localca, vaultpki) that build SANs directly.
func SplitNames(names []string) (dns []string, ips []net.IP) {
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, n)
	}
	return dns, ips
}

// generateKey creates a fresh private key of the given type.
func generateKey(kt KeyType) (crypto.Signer, error) {
	switch kt {
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type %q", kt)
	}
}

// NewKeyAndCSR builds the key and CSR for req: a fresh key of req.KeyType,
// or the caller-supplied req.ReuseKeyPKCS8 when set (a renewal keeping the
// same key). The CSR carries req.Names[0] as its common name and the rest
// as DNS/IP SANs (via SplitNames). Used by localca and vaultpki, whose CAs
// need both the private key and an encodable CSR; acme instead hands lego
// the reused key directly (obtainRequest) since it builds its own CSR.
//
// NewKeyAndCSR zeroes its copy of req.ReuseKeyPKCS8 once the key is parsed
// (the caller's key material should not be kept around any longer than
// needed).
func NewKeyAndCSR(req IssueRequest) (key crypto.Signer, pkcs8, csrDER []byte, err error) {
	if len(req.Names) == 0 {
		return nil, nil, nil, errors.New("signer: at least one name is required")
	}
	if len(req.ReuseKeyPKCS8) > 0 {
		defer clear(req.ReuseKeyPKCS8)
		parsed, err := x509.ParsePKCS8PrivateKey(req.ReuseKeyPKCS8)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse reused key: %w", err)
		}
		signerKey, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, nil, nil, fmt.Errorf("reused key of type %T is not a signer", parsed)
		}
		key = signerKey
	} else {
		key, err = generateKey(req.KeyType)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	dns, ips := SplitNames(req.Names)
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: req.Names[0]},
		DNSNames:    dns,
		IPAddresses: ips,
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create csr: %w", err)
	}
	pkcs8, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return key, pkcs8, csrDER, nil
}
