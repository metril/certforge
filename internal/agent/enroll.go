package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

// verifyPinned accepts the server only if its chain contains the CA the
// token pins and the leaf verifies under it as a server certificate. The
// host name is not checked here: the pin is stronger than a name.
func verifyPinned(raw [][]byte, fp string) error {
	if len(raw) == 0 {
		return errors.New("agent: server sent no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	var anchor *x509.Certificate
	for _, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return err
		}
		certs = append(certs, c)
		if agentproto.CertFingerprint(c.Raw) == fp {
			anchor = c
		}
	}
	if anchor == nil {
		return errors.New("agent: the server's certificate chain does not contain the CA pinned by the token")
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

// enrollTransport accepts a server whose TLS chain either contains the CA the
// token pins or is trusted by the system roots (a public proxy certificate).
// TLS is only hygiene here: the enrolment exchange authenticates the server
// itself, so a hostile terminating proxy gains nothing from passing it.
func enrollTransport(fp string) http.RoundTripper {
	return &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Standard verification is replaced, not skipped: VerifyConnection
		// below requires the pinned CA or a system-trusted chain.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, len(cs.PeerCertificates))
			for i, c := range cs.PeerCertificates {
				raw[i] = c.Raw
			}
			pinErr := verifyPinned(raw, fp)
			if pinErr == nil {
				return nil
			}
			opts := x509.VerifyOptions{DNSName: cs.ServerName, Intermediates: x509.NewCertPool()}
			for _, ic := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(ic)
			}
			if _, err := cs.PeerCertificates[0].Verify(opts); err == nil {
				return nil
			}
			return pinErr
		},
	}}
}

// EnrollOptions tune Enroll.
type EnrollOptions struct {
	// Log receives the verification code and progress; nil means slog.Default().
	Log *slog.Logger
	// Transport carries every request; nil means a TLS transport that accepts
	// the token's CA pin or the system roots.
	Transport http.RoundTripper
}

// Poll intervals while waiting for approval: the first poll is immediate,
// then the wait grows from the minimum to the maximum with jitter.
var (
	EnrollPollMin = 2 * time.Second
	EnrollPollMax = 30 * time.Second
)

// maxPollFailures is how many polls in a row may fail to reach or verify the
// server before enrolment gives up.
const maxPollFailures = 10

// Enroll is EnrollWith with default options.
func Enroll(ctx context.Context, dir, token string, facts agentproto.Facts) (*Identity, error) {
	return EnrollWith(ctx, EnrollOptions{}, dir, token, facts)
}

// enroller holds one enrolment's connection state.
type enroller struct {
	hc      *http.Client
	tok     agentproto.Token
	au      string
	pool    *x509.CertPool
	signers map[string]*ecdsa.PublicKey
	now     func() time.Time
}

// verify requires resp to be signed by a responder certificate chaining to the
// pinned CA, for exactly the request that sent nonce.
func (e *enroller) verify(resp *http.Response, raw []byte, nonce string) error {
	der, err := base64.StdEncoding.DecodeString(resp.Header.Get(agentproto.HeaderSignerCert))
	if err != nil || len(der) == 0 {
		return ErrUnsigned
	}
	pub := e.signers[string(der)]
	if pub == nil {
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			return ErrUnsigned
		}
		if pub, err = agentproto.VerifyResponder(leaf, e.pool, e.now()); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsigned, err)
		}
		e.signers[string(der)] = pub
	}
	if _, err := agentproto.VerifyResponse(resp.Header, resp.StatusCode, raw, nonce, e.now(), pub); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsigned, err)
	}
	return nil
}

func (e *enroller) do(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	resp, err := e.hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, nil, err
	}
	raw, err := readResponse(resp)
	return resp, raw, err
}

// unverified explains a response that failed verification: it says nothing
// the server vouched for, so it can only be a hint.
func unverified(resp *http.Response, err error) error {
	hint := ""
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		hint = "; the token may be invalid, already used or expired, or something between this host and the server is altering traffic"
	}
	return fmt.Errorf("%w (status %d, code %q%s)", err, resp.StatusCode, resp.Header.Get(agentproto.HeaderError), hint)
}

// hello fetches and verifies the server's one-off ephemeral key.
func (e *enroller) hello(ctx context.Context) (agentproto.EnrollHello, *ecdh.PublicKey, error) {
	nonce := agentproto.NewNonce()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.tok.AgentURL+agentproto.PathEnrollHello+"?nonce="+nonce, nil)
	if err != nil {
		return agentproto.EnrollHello{}, nil, err
	}
	resp, raw, err := e.do(ctx, req) //nolint:bodyclose // do reads and closes the body
	if err != nil {
		return agentproto.EnrollHello{}, nil, err
	}
	var h agentproto.EnrollHello
	pinned := false
	if resp.StatusCode == http.StatusOK && json.Unmarshal(raw, &h) == nil {
		e.pool = x509.NewCertPool()
		for _, c := range h.Chain {
			if der, err := base64.StdEncoding.DecodeString(c); err == nil && agentproto.CertFingerprint(der) == e.tok.CAFingerprint {
				if cert, err := x509.ParseCertificate(der); err == nil {
					e.pool.AddCert(cert)
					pinned = true
				}
			}
		}
	}
	if !pinned {
		return h, nil, fmt.Errorf("agent: the server's responder chain does not contain the CA pinned by the token (status %d)", resp.StatusCode)
	}
	if err := e.verify(resp, raw, nonce); err != nil {
		return h, nil, unverified(resp, err)
	}
	pub, err := parseP256(h.Ephemeral)
	if err != nil || h.ID == "" {
		return h, nil, errors.New("agent: malformed enrolment hello")
	}
	return h, pub, nil
}

func parseP256(b64 string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPublicKey(raw)
}

// openReply opens a verified, sealed reply; a non-2xx status becomes a ProblemError.
func openReply(resp *http.Response, raw []byte, priv *ecdh.PrivateKey, path, nonce string, out any) error {
	pt, err := agentproto.HPKEOpen(priv, agentproto.SealInfo(agentproto.DirS2C, path, nonce), raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsigned, err)
	}
	if resp.StatusCode != http.StatusOK {
		var p struct{ Title, Detail string }
		_ = json.Unmarshal(pt, &p)
		if p.Title == "" {
			p.Title = http.StatusText(resp.StatusCode)
		}
		return &ProblemError{Status: resp.StatusCode, Title: p.Title, Detail: p.Detail}
	}
	return json.Unmarshal(pt, out)
}

// submit redeems the token: the sealed proof of possession and the CSR.
func (e *enroller) submit(ctx context.Context, h agentproto.EnrollHello, srv *ecdh.PublicKey, token string, key *ecdsa.PrivateKey, csr []byte, facts agentproto.Facts) (agentproto.EnrollAccepted, error) {
	csrDER, err := agentproto.CSRDER(string(csr))
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	replyPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	th := agentproto.TokenHash(token)
	now := e.now()
	sub := agentproto.EnrollSubmit{LookupID: agentproto.LookupID(th), CSR: string(csr), Facts: facts, Created: now.Unix(),
		Nonce: agentproto.NewNonce(), Reply: base64.StdEncoding.EncodeToString(replyPriv.PublicKey().Bytes())}
	sub.Pop = agentproto.EnrollPop(th, csrDER, e.au, sub.Created, sub.Nonce, sub.Reply)
	pt, _ := json.Marshal(sub)
	ct, err := agentproto.HPKESeal(srv, agentproto.SealInfo(agentproto.DirC2S, agentproto.PathEnroll, h.ID), pt)
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tok.AgentURL+agentproto.PathEnroll, bytes.NewReader(ct))
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(agentproto.HeaderEnrollHello, h.ID)
	resp, raw, err := e.do(ctx, req) //nolint:bodyclose // do reads and closes the body
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	if err := e.verify(resp, raw, h.ID); err != nil {
		return agentproto.EnrollAccepted{}, unverified(resp, err)
	}
	var acc agentproto.EnrollAccepted
	if err := openReply(resp, raw, replyPriv, agentproto.PathEnroll, h.ID, &acc); err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	return acc, nil
}

// poll asks where the request stands, signing with the CSR key.
func (e *enroller) poll(ctx context.Context, key *ecdsa.PrivateKey, acc agentproto.EnrollAccepted) (agentproto.EnrollPoll, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return agentproto.EnrollPoll{}, err
	}
	body, _ := json.Marshal(agentproto.EnrollPollRequest{PollSecret: acc.PollSecret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tok.AgentURL+agentproto.PathEnroll+"/"+acc.ID.String(), bytes.NewReader(body))
	if err != nil {
		return agentproto.EnrollPoll{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	nonce := agentproto.NewNonce()
	if err := agentproto.SignRequest(req, body, key, agentproto.ReqParams{Authority: e.au, KeyID: acc.ID.String(), Nonce: nonce,
		Created: e.now(), Ephemeral: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())}); err != nil {
		return agentproto.EnrollPoll{}, err
	}
	resp, raw, err := e.do(ctx, req) //nolint:bodyclose // do reads and closes the body
	if err != nil {
		return agentproto.EnrollPoll{}, err
	}
	if err := e.verify(resp, raw, nonce); err != nil {
		return agentproto.EnrollPoll{}, unverified(resp, err)
	}
	if code := resp.Header.Get(agentproto.HeaderError); code != "" {
		return agentproto.EnrollPoll{}, refusal(resp)
	}
	var out agentproto.EnrollPoll
	if err := openReply(resp, raw, priv, req.URL.Path, nonce, &out); err != nil {
		return agentproto.EnrollPoll{}, err
	}
	return out, nil
}

// waitApproved polls until the request is approved. A verified refusal
// (wrong poll secret, client re-enrolled) is final; an unreachable or
// unverifiable server is retried with backoff a few times.
func (e *enroller) waitApproved(ctx context.Context, key *ecdsa.PrivateKey, acc agentproto.EnrollAccepted, log *slog.Logger) (agentproto.EnrollPoll, error) {
	b := backoff{min: EnrollPollMin, max: EnrollPollMax}
	failures := 0
	for {
		res, err := e.poll(ctx, key, acc)
		var pe *ProblemError
		switch {
		case errors.As(err, &pe):
			return res, fmt.Errorf("enrol: %w", err)
		case err != nil:
			if failures++; failures >= maxPollFailures || ctx.Err() != nil {
				return res, fmt.Errorf("enrol: %w", err)
			}
			log.Warn("enrolment poll failed; retrying", "err", err)
		default:
			failures = 0
			switch res.Status {
			case agentproto.EnrollApproved:
				return res, nil
			case agentproto.EnrollRejected:
				return res, errors.New("enrol: an administrator rejected this agent's request; ask for a new token")
			case agentproto.EnrollExpired:
				return res, errors.New("enrol: the request expired before it was approved; ask for a new token if this token has expired too, or start the agent again")
			}
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(b.next()):
		}
	}
}

// Enroll exchanges a one-time token for this agent's certificate. The key is
// created once (agent.key, 0600) and reused by later enrolments; grants
// already recorded in state.json are kept so a re-enrolled agent still
// knows which files it wrote.
//
// The server may hold the request until an administrator approves it; Enroll
// logs the verification code to compare, then polls with backoff until the
// certificate arrives, the request is rejected or expires, or ctx ends.
func EnrollWith(ctx context.Context, opts EnrollOptions, dir, token string, facts agentproto.Facts) (*Identity, error) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	tok, err := agentproto.ParseToken(token)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(dir)
	if err != nil {
		return nil, err
	}
	csr, err := csrPEM(key)
	if err != nil {
		return nil, err
	}
	rt := opts.Transport
	if rt == nil {
		rt = enrollTransport(tok.CAFingerprint)
	}
	e := &enroller{hc: &http.Client{Transport: rt, Timeout: 30 * time.Second}, tok: tok, au: agentproto.Authority(tok.AgentURL),
		pool: x509.NewCertPool(), signers: map[string]*ecdsa.PublicKey{}, now: time.Now}
	h, srvKey, err := e.hello(ctx)
	if err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}
	acc, err := e.submit(ctx, h, srvKey, token, key, csr, facts)
	if err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if want := agentproto.VerifyCode(pubDER, tok.CAFingerprint); want != acc.VerifyCode {
		return nil, fmt.Errorf("enrol: the verification code from the server (%s) does not match this agent's (%s); it is not talking to the CA in its token",
			agentproto.FormatVerifyCode(acc.VerifyCode), agentproto.FormatVerifyCode(want))
	}
	if acc.Status == agentproto.EnrollPending {
		log.Warn("ENROLMENT WAITING FOR APPROVAL: an administrator must approve this agent in CertForge (Clients, Pending approval) after checking that its verification code matches",
			"verification_code", agentproto.FormatVerifyCode(acc.VerifyCode), "server", tok.AgentURL, "expires", acc.ExpiresAt.Format(time.RFC3339))
	}
	er, err := e.waitApproved(ctx, key, acc, log)
	if err != nil {
		return nil, err
	}
	if err := requireHTTPS(er.AgentURL); err != nil {
		return nil, err
	}
	// Validate the certificate and derive its client id before writing
	// anything: a bad response must leave the data directory untouched.
	cert, err := parseCert([]byte(er.Certificate), key)
	if err != nil {
		return nil, err
	}
	clientID, err := clientIDFromCert(cert)
	if err != nil {
		return nil, err
	}
	id := &Identity{Dir: dir, Key: key, State: State{Grants: map[uuid.UUID]GrantState{}}}
	switch prev, err := os.ReadFile(filepath.Join(dir, stateFile)); {
	case err == nil:
		if err := json.Unmarshal(prev, &id.State); err != nil {
			return nil, fmt.Errorf("agent: state.json: %w", err)
		}
		if id.State.Grants == nil {
			id.State.Grants = map[uuid.UUID]GrantState{}
		}
	case errors.Is(err, fs.ErrNotExist):
		// fresh enrolment: no prior grants to keep
	default:
		return nil, err
	}
	// Write order matters: ca.pem and state.json first, agent.crt last, so a
	// crash mid-enrolment leaves ErrNotEnrolled rather than a half-written
	// identity that LoadIdentity would otherwise accept.
	if err := id.commitBundle([]byte(er.TrustBundle)); err != nil {
		return nil, err
	}
	id.State.AgentURL = strings.TrimRight(er.AgentURL, "/")
	if id.State.AgentURL == "" {
		id.State.AgentURL = tok.AgentURL
	}
	id.State.ClientID, id.State.TokenHash, id.State.Revision = clientID, TokenHashHex(token), 0
	if err := id.SaveState(); err != nil {
		return nil, err
	}
	if err := id.commitCert([]byte(er.Certificate)); err != nil {
		return nil, err
	}
	return id, nil
}
