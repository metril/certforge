package httpx

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// NormalizeCABundle validates a pasted CA trust bundle and returns it in
// canonical form: CRLF/CR line endings become LF and surrounding whitespace
// is trimmed. An empty (or blank) bundle is valid and returns "". A
// non-empty one must hold at least one PEM CERTIFICATE block, every block
// must be a certificate (a pasted private key is refused), and each must
// parse as X.509.
func NormalizeCABundle(s string) (string, error) {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"))
	if s == "" {
		return "", nil
	}
	rest := []byte(s)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return "", fmt.Errorf("contains a %q PEM block; only CERTIFICATE blocks are allowed", b.Type)
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return "", fmt.Errorf("certificate %d is not a valid X.509 certificate: %v", n+1, err)
		}
		n++
	}
	if n == 0 {
		return "", errors.New("must contain at least one PEM CERTIFICATE block (-----BEGIN CERTIFICATE-----)")
	}
	return s, nil
}
