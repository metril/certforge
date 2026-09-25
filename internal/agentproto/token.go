package agentproto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ErrBadToken means a string is not a well-formed enrolment token.
var ErrBadToken = errors.New("agentproto: malformed enrolment token")

var fpRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Token is a parsed cf1.<base64url(agentUrl)>.<CA sha256 hex>.<secret> token.
type Token struct {
	AgentURL      string
	CAFingerprint string
	Secret        string // base64url of 32 random bytes
}

// NewToken returns a fresh token string for agentURL pinned to caFingerprint.
// It validates both inputs so the result always round-trips through
// ParseToken.
func NewToken(agentURL, caFingerprint string) (string, error) {
	u, err := url.Parse(agentURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("%w: agent URL must be https://host[:port]", ErrBadToken)
	}
	if !fpRe.MatchString(caFingerprint) {
		return "", fmt.Errorf("%w: CA fingerprint must be 64 lowercase hex digits", ErrBadToken)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.Join([]string{"cf1",
		base64.RawURLEncoding.EncodeToString([]byte(agentURL)),
		caFingerprint,
		base64.RawURLEncoding.EncodeToString(b)}, "."), nil
}

// ParseToken validates and splits s (surrounding space is ignored).
func ParseToken(s string) (Token, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 4 || parts[0] != "cf1" {
		return Token{}, fmt.Errorf("%w: expected cf1.<url>.<fingerprint>.<secret>", ErrBadToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Token{}, fmt.Errorf("%w: agent URL is not base64url", ErrBadToken)
	}
	u, err := url.Parse(string(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return Token{}, fmt.Errorf("%w: agent URL must be https://host[:port]", ErrBadToken)
	}
	if !fpRe.MatchString(parts[2]) {
		return Token{}, fmt.Errorf("%w: CA fingerprint must be 64 lowercase hex digits", ErrBadToken)
	}
	if sec, err := base64.RawURLEncoding.DecodeString(parts[3]); err != nil || len(sec) != 32 {
		return Token{}, fmt.Errorf("%w: secret must be 32 bytes of base64url", ErrBadToken)
	}
	return Token{AgentURL: strings.TrimRight(string(raw), "/"), CAFingerprint: parts[2], Secret: parts[3]}, nil
}

// TokenHash is the sha256 stored for a token (hashed at rest).
func TokenHash(s string) []byte {
	h := sha256.Sum256([]byte(strings.TrimSpace(s)))
	return h[:]
}
