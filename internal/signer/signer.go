// Package signer defines the certificate signing abstraction. Implementations
// live in sub-packages (acme in Phase 1; localca and vaultpki in Phase 5).
package signer

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// KeyType is the certificate key algorithm as stored and shown in the API.
type KeyType string

const (
	RSA2048 KeyType = "rsa2048"
	RSA3072 KeyType = "rsa3072"
	RSA4096 KeyType = "rsa4096"
	EC256   KeyType = "ec256"
	EC384   KeyType = "ec384"
)

// Valid reports whether k is a supported key type.
func (k KeyType) Valid() bool {
	switch k {
	case RSA2048, RSA3072, RSA4096, EC256, EC384:
		return true
	}
	return false
}

// AccountMaterial is a decrypted ACME account: contact, PKCS#8 key and kid.
type AccountMaterial struct {
	Email           string
	KeyPKCS8        []byte
	RegistrationURI string
}

// ChallengeSolver is what a Signer needs to prove control of names.
// challenge.Router implements it. Present/CleanUp/Timeout match lego's
// challenge.Provider and challenge.ProviderTimeout; PreCheck is installed via
// dns01.WrapPreCheck. ChallengeTypes/TypeFor/For make it type-aware
// (Phase 4A): a single-method Issue registers For(the one type) with lego;
// more than one type is rejected until mixed-method ordering arrives.
type ChallengeSolver interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
	Timeout() (timeout, interval time.Duration)
	PreCheck(domain, fqdn, value string, check func(fqdn, value string) (bool, error)) (bool, error)

	// ChallengeTypes lists the distinct challenge types ("dns-01", "http-01",
	// "tls-alpn-01") this solver's rules use.
	ChallengeTypes() []string
	// TypeFor reports the challenge type used for name.
	TypeFor(name string) (string, error)
	// For returns the view of this solver restricted to challenge type t:
	// its Present/CleanUp/PreCheck consider only rules of that type, so
	// registering it as a single lego provider cannot reach a rule of a
	// different type sharing the same bare authorization domain.
	For(t string) ChallengeSolver
}

// IssueRequest asks a Signer for one certificate covering Names.
type IssueRequest struct {
	Names          []string // first entry is the common name
	KeyType        KeyType
	PreferredChain string
	MustStaple     bool
	ReuseKeyPKCS8  []byte // nil = generate a fresh key
	Account        AccountMaterial
	Challenge      ChallengeSolver
}

// Issued is canonical certificate material: leaf DER, chain DER, PKCS#8 key.
type Issued struct {
	LeafDER         []byte
	ChainDER        [][]byte
	PrivateKeyPKCS8 []byte
	NotBefore       time.Time
	NotAfter        time.Time
	Serial          string // lower-case hex
}

// Window is an ARI suggested renewal window.
type Window struct {
	Start, End time.Time
	RetryAfter time.Duration
}

// Signer issues, revokes and reports renewal info for certificates.
type Signer interface {
	Kind() string
	Issue(ctx context.Context, req IssueRequest) (*Issued, error)
	Revoke(ctx context.Context, cert *x509.Certificate, reason int) error
	RenewalInfo(ctx context.Context, cert *x509.Certificate) (*Window, error)
}

// DirectoryInfo is implemented by a Signer that can report its ACME
// directory's published caaIdentities (RFC 8555 §7.1.1 meta). The issuance
// worker's CAA pre-check type-asserts a Signer against this; a Signer
// without it (localca, vaultpki in Phase 5) has nothing to check against,
// so the step succeeds without evaluating CAA.
type DirectoryInfo interface {
	CAAIdentities(ctx context.Context) ([]string, error)
}

// Error is a classified CA failure. Type is the full ACME problem URN when the
// CA returned one; RetryAfter is the largest Retry-After seen on 429/503.
type Error struct {
	Type       string
	Detail     string
	Status     int
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	msg := e.Detail
	if e.Err != nil {
		msg = e.Err.Error()
	} else if msg == "" {
		msg = "signer error"
	}
	if e.Type == "" {
		return msg
	}
	return fmt.Sprintf("%s (%s)", msg, e.ShortType())
}

func (e *Error) Unwrap() error { return e.Err }

// ShortType strips the ACME URN prefix: "urn:ietf:params:acme:error:rateLimited" -> "rateLimited".
func (e *Error) ShortType() string {
	return strings.TrimPrefix(e.Type, "urn:ietf:params:acme:error:")
}
