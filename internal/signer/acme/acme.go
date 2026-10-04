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
	"sync"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
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

// Signer talks to one ACME directory. It is cheap to build; the ACME
// directory itself is fetched from the network the first time a call
// actually needs it, and (for RenewalInfo only — fix round 1, "fetch each
// CA's directory once per run") cached on the instance from then on, so a
// caller polling many certificates of the same CA through one Signer
// instance (ARIPollWorker) fetches it once, not once per certificate.
type Signer struct {
	cfg Config
	now func() time.Time

	// riMu guards the cached RenewalInfo client: it is built on first use
	// and kept on success only; a build error is remembered for riErrTTL.
	riMu    sync.Mutex
	riCl    *lego.Client
	riRT    *retryAfterTransport
	riErr   error
	riErrAt time.Time
	// riCall serialises RenewalInfo requests so riRT's largest-Retry-After
	// can be reset per request (concurrent callers share one Signer).
	riCall sync.Mutex
}

// riErrTTL is how long a failed RenewalInfo client build (an unreachable
// directory) is remembered, so one transient failure does not fail every
// certificate on the CA for the whole run, nor retry the fetch per call.
const riErrTTL = 30 * time.Second

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
	if len(req.Challenge.ChallengeTypes()) > 1 {
		return s.issueMixed(ctx, u, kt, req)
	}
	cl, rt, err := s.client(ctx, u, kt)
	if err != nil {
		return nil, err
	}
	if err := registerChallengeSolver(cl, req.Challenge); err != nil {
		return nil, err
	}
	or, err := obtainRequest(req)
	if err != nil {
		return nil, err
	}
	res, err := cl.Certificate.Obtain(or)
	if err != nil {
		return nil, classify(err, rt)
	}
	return signer.IssuedFromPEM(res.Certificate, res.PrivateKey)
}

// obtainRequest builds the certificate.ObtainRequest shared by the
// single-method path (Obtain, above) and the mixed-method path (issueMixed,
// orderflow.go): domains, bundling, must-staple, preferred chain, and an
// optional reused key parsed from PKCS#8.
func obtainRequest(req signer.IssueRequest) (certificate.ObtainRequest, error) {
	or := certificate.ObtainRequest{
		Domains:        req.Names,
		Bundle:         true,
		MustStaple:     req.MustStaple,
		PreferredChain: req.PreferredChain,
	}
	if len(req.ReuseKeyPKCS8) > 0 {
		// The parsed key is the only copy needed from here on (same as
		// signer.NewKeyAndCSR).
		defer clear(req.ReuseKeyPKCS8)
		pk, err := x509.ParsePKCS8PrivateKey(req.ReuseKeyPKCS8)
		if err != nil {
			return certificate.ObtainRequest{}, fmt.Errorf("parse reused key: %w", err)
		}
		or.PrivateKey = pk
	}
	if req.Replaces != nil {
		id, err := certificate.MakeARICertID(req.Replaces)
		if err != nil {
			return certificate.ObtainRequest{}, fmt.Errorf("ari replaces cert id: %w", err)
		}
		or.ReplacesCertID = id
	}
	return or, nil
}

// registerChallengeSolver registers solver's single challenge type as the
// matching lego provider. Issue only calls this once req.Challenge resolves
// to exactly one type; a certificate whose names span more than one type
// goes through issueMixed (orderflow.go, ADR 0012) instead, which drives
// lego's SolverManager-free certificate.NewCertifier with a resolver of our
// own. For each type this registers solver.For(type), not solver itself, so
// a single lego provider can only ever reach rules of that one type.
func registerChallengeSolver(cl *lego.Client, solver signer.ChallengeSolver) error {
	types := solver.ChallengeTypes()
	if len(types) != 1 {
		return fmt.Errorf("registerChallengeSolver called with %d challenge types, want 1", len(types))
	}
	switch types[0] {
	case "dns-01":
		view := solver.For("dns-01")
		return cl.Challenge.SetDNS01Provider(view, dns01.WrapPreCheck(
			func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
				return view.PreCheck(domain, fqdn, value, check)
			}))
	case "http-01":
		return cl.Challenge.SetHTTP01Provider(solver.For("http-01"))
	case "tls-alpn-01":
		return cl.Challenge.SetTLSALPN01Provider(solver.For("tls-alpn-01"))
	default:
		return fmt.Errorf("unsupported challenge type %q", types[0])
	}
}

// CAAIdentities implements signer.DirectoryInfo: it fetches the ACME
// directory and returns the caaIdentities it publishes (RFC 8555 §7.1.1),
// used by the CAA pre-check before any order. No account key is needed to
// read the directory, so this works even before an account is registered.
func (s *Signer) CAAIdentities(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hc, rt, err := s.httpClient(ctx)
	if err != nil {
		return nil, err
	}
	core, err := api.New(hc, s.cfg.UserAgent, s.cfg.DirectoryURL, "", nil)
	if err != nil {
		return nil, classify(err, rt)
	}
	return core.GetDirectory().Meta.CaaIdentities, nil
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

// renewalInfoUser returns the user RenewalInfo builds its lego client with.
// GetRenewalInfo is an unauthenticated GET per RFC 9773 (no JWS is ever
// sent), but lego.NewClient still requires a private key to construct its
// JWS signer regardless. cfg.Account is used when the caller has one (the
// post-issuance poll, run alongside a real Issue); an empty Account (the
// periodic ARIPollWorker, which never loads or decrypts an ACME account
// key just to poll a window) falls back to a fresh ephemeral P-256 key.
func (s *Signer) renewalInfoUser() (*user, error) {
	if len(s.cfg.Account.KeyPKCS8) == 0 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &user{email: s.cfg.Account.Email, key: key}, nil
	}
	return accountUser(s.cfg.Account)
}

// RenewalInfo fetches the ARI window (Task 12: the post-issuance poll and
// the periodic ARIPollWorker, internal/issuance/ari.go).
func (s *Signer) RenewalInfo(ctx context.Context, cert *x509.Certificate) (*signer.Window, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cl, rt, err := s.renewalInfoClient(ctx)
	if err != nil {
		return nil, err
	}
	s.riCall.Lock()
	defer s.riCall.Unlock()
	rt.reset()
	ri, err := cl.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: cert})
	if err != nil {
		return nil, classify(err, rt)
	}
	return &signer.Window{Start: ri.SuggestedWindow.Start, End: ri.SuggestedWindow.End, RetryAfter: ri.RetryAfter}, nil
}

// renewalInfoClient builds the lego client (and so fetches the ACME
// directory) once per Signer instance and reuses it on every later
// RenewalInfo call. Only success is cached for good: a failure is cached
// for riErrTTL (fix round 2). ARIPollWorker caches one Signer per CA
// across a whole poll run (internal/issuance/ari.go), so many certificates
// on the same CA share one directory fetch. The client is built on a
// context detached from the first caller's cancellation, since later
// callers reuse it; GetRenewalInfo itself is an unauthenticated GET
// (RFC 9773).
func (s *Signer) renewalInfoClient(ctx context.Context) (*lego.Client, *retryAfterTransport, error) {
	s.riMu.Lock()
	defer s.riMu.Unlock()
	if s.riCl != nil {
		return s.riCl, s.riRT, nil
	}
	if s.riErr != nil && s.now().Sub(s.riErrAt) < riErrTTL {
		return nil, nil, s.riErr
	}
	u, err := s.renewalInfoUser()
	if err == nil {
		var cl *lego.Client
		var rt *retryAfterTransport
		if cl, rt, err = s.client(context.WithoutCancel(ctx), u, certcrypto.EC256); err == nil {
			s.riCl, s.riRT, s.riErr = cl, rt, nil
			return cl, rt, nil
		}
	}
	s.riErr, s.riErrAt = err, s.now()
	return nil, nil, err
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
