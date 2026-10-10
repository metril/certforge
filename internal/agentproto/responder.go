package agentproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"time"
)

// ResponderMarker is the OU of a responder certificate (an RFC 4122 UUID
// arc OID). Go's x509 cannot parse a certificate carrying an OID arc this
// large, so it cannot be the EKU itself. The EKU is OCSPSigning, which no TLS
// stack accepts for serverAuth or clientAuth; the marker tells responder
// certificates apart from other OCSPSigning ones.
const ResponderMarker = "2.25.284011506363329835389774668932300182646"

// VerifyResponder checks that leaf chains to roots and carries the responder EKU and
// marker only; it returns the leaf's ECDSA public key. It lives here, free of
// database dependencies, because the agent binary uses it.
func VerifyResponder(leaf *x509.Certificate, roots *x509.CertPool, now time.Time) (*ecdsa.PublicKey, error) {
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageOCSPSigning || len(leaf.UnknownExtKeyUsage) != 0 ||
		len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != ResponderMarker {
		return nil, errors.New("agentproto: not a responder certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, err
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("agentproto: responder key must be ECDSA P-256")
	}
	return pub, nil
}
