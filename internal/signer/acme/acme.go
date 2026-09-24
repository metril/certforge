// Package acme implements signer.Signer on top of lego v4 for any ACME CA.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/metril/certforge/internal/signer"
)

// Config selects the CA. Account is used by Revoke and RenewalInfo; Issue uses
// IssueRequest.Account.
type Config struct {
	DirectoryURL   string
	TrustBundlePEM string // extra roots for private ACME servers (Pebble, step-ca)
	UserAgent      string
	Account        signer.AccountMaterial
}

// EAB is External Account Binding material (kid + base64url HMAC key).
type EAB struct{ KID, HMAC string }

// Signer talks to one ACME directory. It is cheap; build one per job.
type Signer struct {
	cfg Config
	now func() time.Time
}

// New returns a Signer for cfg.
func New(cfg Config) *Signer {
	if cfg.UserAgent == "" {
		cfg.UserAgent = "certforge"
	}
	return &Signer{cfg: cfg, now: time.Now}
}

func (s *Signer) Kind() string { return "acme" }

type user struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *user) GetEmail() string                        { return u.email }
func (u *user) GetRegistration() *registration.Resource { return u.reg }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

func legoKeyType(k signer.KeyType) (certcrypto.KeyType, error) {
	switch k {
	case signer.RSA2048:
		return certcrypto.RSA2048, nil
	case signer.RSA3072:
		return certcrypto.RSA3072, nil
	case signer.RSA4096:
		return certcrypto.RSA4096, nil
	case signer.EC256:
		return certcrypto.EC256, nil
	case signer.EC384:
		return certcrypto.EC384, nil
	}
	return "", fmt.Errorf("unsupported key type %q", k)
}

// ctxTransport aborts a request immediately once ctx is done, and attaches
// ctx to every outgoing request so a cancellation reaches an in-flight round
// trip too. lego v4 is not context-aware on its own: without this, cancelling
// the issuance context would stop the challenge solver (manual-dns waits
// honour it) but leave an in-flight CA HTTP call running until it completes
// or times out.
type ctxTransport struct {
	base http.RoundTripper
	ctx  context.Context
}

func (t *ctxTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	// r.WithContext replaces r's context, including the deadline
	// net/http.Client.do already derived from it to enforce httpClient's own
	// Timeout (60s, set below) — so that per-request wall-clock timeout does
	// not simply stop working here. Request.WithContext copies every other
	// field of r unchanged, including the legacy Cancel channel Client.do
	// also wires up alongside that context deadline; net/http's own
	// Transport.RoundTrip still selects on req.Cancel for backward
	// compatibility, so httpClient's Timeout keeps firing through that path
	// even though the context carrying its deadline was replaced here.
	return t.base.RoundTrip(r.WithContext(t.ctx))
}

func (s *Signer) httpClient(ctx context.Context) (*http.Client, *retryAfterTransport, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if s.cfg.TrustBundlePEM != "" && !pool.AppendCertsFromPEM([]byte(s.cfg.TrustBundlePEM)) {
		return nil, nil, errors.New("trust bundle contains no PEM certificates")
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	rt := &retryAfterTransport{base: base, now: s.now}
	return &http.Client{Transport: &ctxTransport{base: rt, ctx: ctx}, Timeout: 60 * time.Second}, rt, nil
}

func (s *Signer) client(ctx context.Context, u *user, kt certcrypto.KeyType) (*lego.Client, *retryAfterTransport, error) {
	hc, rt, err := s.httpClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = s.cfg.DirectoryURL
	cfg.UserAgent = s.cfg.UserAgent
	cfg.HTTPClient = hc
	cfg.Certificate.KeyType = kt
	cl, err := lego.NewClient(cfg)
	if err != nil {
		return nil, rt, classify(err, rt)
	}
	return cl, rt, nil
}

func accountUser(a signer.AccountMaterial) (*user, error) {
	key, err := x509.ParsePKCS8PrivateKey(a.KeyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}
	return &user{email: a.Email, key: key, reg: &registration.Resource{URI: a.RegistrationURI}}, nil
}

// Register creates a new ACME account with a fresh P-256 key, using EAB when
// eab is non-nil.
func (s *Signer) Register(ctx context.Context, email string, eab *EAB) (signer.AccountMaterial, error) {
	if err := ctx.Err(); err != nil {
		return signer.AccountMaterial{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return signer.AccountMaterial{}, err
	}
	u := &user{email: email, key: key}
	cl, rt, err := s.client(ctx, u, certcrypto.EC256)
	if err != nil {
		return signer.AccountMaterial{}, err
	}
	var reg *registration.Resource
	if eab != nil && eab.KID != "" {
		reg, err = cl.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true, Kid: eab.KID, HmacEncoded: eab.HMAC,
		})
	} else {
		reg, err = cl.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return signer.AccountMaterial{}, classify(err, rt)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return signer.AccountMaterial{}, err
	}
	return signer.AccountMaterial{Email: email, KeyPKCS8: pk, RegistrationURI: reg.URI}, nil
}

// Issue obtains a certificate. lego v4 is not context-aware on its own: ctx is
// checked before ordering, and it reaches the challenge solver (manual-dns
// waits observe it) directly; in-flight CA HTTP calls are made to observe it
// too via ctxTransport, which attaches ctx to every request lego sends.
func (s *Signer) Issue(ctx context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Challenge == nil {
		return nil, errors.New("no challenge solver")
	}
	kt, err := legoKeyType(req.KeyType)
	if err != nil {
		return nil, err
	}
	u, err := accountUser(req.Account)
	if err != nil {
		return nil, err
	}
	cl, rt, err := s.client(ctx, u, kt)
	if err != nil {
		return nil, err
	}
	solver := req.Challenge
	err = cl.Challenge.SetDNS01Provider(solver, dns01.WrapPreCheck(
		func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			return solver.PreCheck(domain, fqdn, value, check)
		}))
	if err != nil {
		return nil, err
	}
	or := certificate.ObtainRequest{
		Domains:        req.Names,
		Bundle:         true,
		MustStaple:     req.MustStaple,
		PreferredChain: req.PreferredChain,
	}
	if len(req.ReuseKeyPKCS8) > 0 {
		pk, err := x509.ParsePKCS8PrivateKey(req.ReuseKeyPKCS8)
		if err != nil {
			return nil, fmt.Errorf("parse reused key: %w", err)
		}
		or.PrivateKey = pk
	}
	res, err := cl.Certificate.Obtain(or)
	if err != nil {
		return nil, classify(err, rt)
	}
	return signer.IssuedFromPEM(res.Certificate, res.PrivateKey)
}

// Revoke revokes cert with an RFC 5280 reason code using cfg.Account.
func (s *Signer) Revoke(ctx context.Context, cert *x509.Certificate, reason int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u, err := accountUser(s.cfg.Account)
	if err != nil {
		return err
	}
	cl, rt, err := s.client(ctx, u, certcrypto.EC256)
	if err != nil {
		return err
	}
	r := uint(reason)
	if err := cl.Certificate.RevokeWithReason(certcrypto.PEMEncode(certcrypto.DERCertificateBytes(cert.Raw)), &r); err != nil {
		return classify(err, rt)
	}
	return nil
}

// RenewalInfo fetches the ARI window (stored for Phase 4; unused in Phase 1).
func (s *Signer) RenewalInfo(ctx context.Context, cert *x509.Certificate) (*signer.Window, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u, err := accountUser(s.cfg.Account)
	if err != nil {
		return nil, err
	}
	cl, rt, err := s.client(ctx, u, certcrypto.EC256)
	if err != nil {
		return nil, err
	}
	ri, err := cl.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: cert})
	if err != nil {
		return nil, classify(err, rt)
	}
	return &signer.Window{Start: ri.SuggestedWindow.Start, End: ri.SuggestedWindow.End, RetryAfter: ri.RetryAfter}, nil
}

func classify(err error, rt *retryAfterTransport) error {
	se := &signer.Error{Err: err}
	if rt != nil {
		se.RetryAfter = rt.RetryAfter()
	}
	var pd *legoacme.ProblemDetails
	if errors.As(err, &pd) {
		se.Type, se.Detail, se.Status = pd.Type, pd.Detail, pd.HTTPStatus
	}
	return se
}
