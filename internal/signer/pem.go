package signer

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// IssuedFromPEM converts a PEM bundle (leaf first, then chain) and a PEM
// private key (PKCS#1, SEC1 or PKCS#8) into canonical Issued material.
func IssuedFromPEM(bundlePEM, keyPEM []byte) (*Issued, error) {
	var ders [][]byte
	rest := bundlePEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			ders = append(ders, b.Bytes)
		}
	}
	if len(ders) == 0 {
		return nil, errors.New("no certificate in bundle")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || !strings.HasSuffix(kb.Type, "PRIVATE KEY") {
		return nil, errors.New("no private key PEM block")
	}
	var key any
	switch kb.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return &Issued{
		LeafDER:         ders[0],
		ChainDER:        ders[1:],
		PrivateKeyPKCS8: pkcs8,
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter,
		Serial:          fmt.Sprintf("%x", leaf.SerialNumber),
	}, nil
}
