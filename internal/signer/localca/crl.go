package localca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

// Revoked is one CRL entry.
type Revoked struct {
	Serial     *big.Int
	RevokedAt  time.Time
	ReasonCode int
}

// BuildCRL signs a new CRL for issuer/key, numbered number, listing
// revoked. ThisUpdate is now; NextUpdate is now + 7 days (the public CRL
// routes' Cache-Control: max-age=600 keeps clients refreshing well before
// that).
func BuildCRL(issuer *x509.Certificate, key crypto.Signer, revoked []Revoked, number *big.Int, now time.Time) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, r := range revoked {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   r.Serial,
			RevocationTime: r.RevokedAt,
			ReasonCode:     r.ReasonCode,
		}
	}
	tmpl := &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
}
