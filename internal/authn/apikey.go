package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// ErrBadAPIKey means the bearer token is malformed, unknown, expired,
// revoked, or its creator is disabled.
var ErrBadAPIKey = errors.New("authn: invalid API key")

// NewAPIKeyToken returns a token "cf_<prefix>_<secret>", its lookup prefix
// (12 hex) and the SHA-256 of the secret (the only part stored).
func NewAPIKeyToken() (token, prefix string, hash []byte, err error) {
	pb := make([]byte, 6)
	sb := make([]byte, 32)
	if _, err = rand.Read(pb); err != nil {
		return
	}
	if _, err = rand.Read(sb); err != nil {
		return
	}
	prefix = hex.EncodeToString(pb)
	secret := base64.RawURLEncoding.EncodeToString(sb)
	return "cf_" + prefix + "_" + secret, prefix, HashAPIKeySecret(secret), nil
}

// ParseAPIKeyToken splits a token into prefix and secret.
func ParseAPIKeyToken(tok string) (prefix, secret string, ok bool) {
	rest, ok := strings.CutPrefix(tok, "cf_")
	if !ok {
		return "", "", false
	}
	prefix, secret, ok = strings.Cut(rest, "_")
	if !ok || len(prefix) != 12 || len(secret) < 43 || strings.Trim(prefix, "0123456789abcdef") != "" {
		return "", "", false
	}
	return prefix, secret, true
}

// HashAPIKeySecret is the stored form of a key secret.
func HashAPIKeySecret(secret string) []byte {
	s := sha256.Sum256([]byte(secret))
	return s[:]
}

// LoadAPIKeyPrincipal is the creator's current principal narrowed to the
// key: its scopes, its org, and any role bindings whose subject is the key.
func LoadAPIKeyPrincipal(ctx context.Context, q *sqlcgen.Queries, creator sqlcgen.User, k sqlcgen.ApiKey) (Principal, error) {
	p, err := LoadPrincipal(ctx, q, creator)
	if err != nil {
		return Principal{}, err
	}
	rbs, err := q.ListRoleBindingsForAPIKey(ctx, k.ID.String())
	if err != nil {
		return Principal{}, err
	}
	info := &APIKeyInfo{ID: k.ID, Scopes: slices.Clone(k.Scopes), OrgID: k.OrgID}
	for _, rb := range rbs {
		if rb.SiteID == nil {
			info.Bindings = append(info.Bindings, Binding{Role: rb.Role, OrgID: rb.OrgID})
		}
	}
	p.Kind, p.APIKey = KindAPIKey, info
	if k.OrgID != nil {
		p.OrgIDs = slices.DeleteFunc(p.OrgIDs, func(id uuid.UUID) bool { return id != *k.OrgID })
	}
	return p, nil
}
