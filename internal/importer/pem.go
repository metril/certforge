package importer

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// decodeCertPEMs returns the DER bytes of every CERTIFICATE block in b, in
// the order they appear.
func decodeCertPEMs(b []byte) [][]byte {
	var out [][]byte
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
	return out
}

// normalizeKeyPEM decodes a PEM private key of any of the three encodings
// acme.sh and certbot both use (PKCS#1, SEC1, PKCS#8) and re-marshals it as
// PKCS#8, the shape certstore always stores. ok is false when b holds no
// recognizable private key.
func normalizeKeyPEM(b []byte) (der []byte, ok bool) {
	block, _ := pem.Decode(b)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, false
	}
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, false
	}
	der, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, false
	}
	return der, true
}
