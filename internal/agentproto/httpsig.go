package agentproto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A pure subset of RFC 9421 HTTP message signatures with one fixed shape per
// message kind; verifiers rebuild the canonical Signature-Input from the
// parsed values and require an exact match. Signatures are ECDSA P-256 over
// SHA-256 as raw r||s (RFC 9421 ecdsa-p256-sha256).

// Header names.
const (
	HeaderSignature      = "Signature"
	HeaderSignatureInput = "Signature-Input"
	HeaderContentDigest  = "Content-Digest"
	HeaderEphemeral      = "Cf-Ephemeral"
	HeaderError          = "Cf-Error"
)

// MaxSkew is how far created may be from the verifier's clock.
const MaxSkew = 120 * time.Second

// Errors.
var (
	ErrSig   = errors.New("agentproto: bad message signature")
	ErrStale = errors.New("agentproto: message signature outside the clock window")
)

const (
	reqComponents  = `("@method" "@authority" "@request-target" "content-digest" "cf-ephemeral")`
	respComponents = `("@status" "content-digest")`
	// respComponentsErr also covers Cf-Error, so a refusal's code is signed.
	respComponentsErr = `("@status" "content-digest" "cf-error")`
	sigLabel          = "sig"
	sigAlg            = "ecdsa-p256-sha256"
)

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_.:\-]{1,200}$`)

// ReqParams are the explicit signature parameters of a request.
type ReqParams struct {
	Authority string // host the request is addressed to, signed as @authority
	KeyID     string // <clientID>:<serialHex>
	Nonce     string
	Created   time.Time
	Ephemeral string // base64 session ephemeral key, sent as Cf-Ephemeral
}

// RespParams are the explicit signature parameters of a response.
type RespParams struct {
	KeyID    string
	ReqNonce string // nonce of the request this answers
	Created  time.Time
	Error    string // refusal code, sent as Cf-Error and signed when not empty
}

// NewNonce returns 16 random bytes, base64url.
func NewNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ContentDigest is the sha-256 Content-Digest value of body.
func ContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"
}

func checkDigest(h http.Header, body []byte) error {
	if subtle.ConstantTimeCompare([]byte(h.Get(HeaderContentDigest)), []byte(ContentDigest(body))) != 1 {
		return fmt.Errorf("%w: content digest", ErrSig)
	}
	return nil
}

func sigParams(comps string, kv ...string) string {
	return comps + strings.Join(kv, "") + `;alg="` + sigAlg + `"`
}

func reqSigParams(p ReqParams) string {
	return sigParams(reqComponents, ";created="+strconv.FormatInt(p.Created.Unix(), 10), `;nonce="`+p.Nonce+`"`, `;keyid="`+p.KeyID+`"`)
}

func respSigParams(p RespParams) string {
	comps := respComponents
	if p.Error != "" {
		comps = respComponentsErr
	}
	return sigParams(comps, ";created="+strconv.FormatInt(p.Created.Unix(), 10), `;req-nonce="`+p.ReqNonce+`"`, `;keyid="`+p.KeyID+`"`)
}

func reqBase(r *http.Request, p ReqParams, digest string) []byte {
	return []byte(`"@method": ` + r.Method + "\n" +
		`"@authority": ` + strings.ToLower(p.Authority) + "\n" +
		`"@request-target": ` + r.URL.RequestURI() + "\n" +
		`"content-digest": ` + digest + "\n" +
		`"cf-ephemeral": ` + p.Ephemeral + "\n" +
		`"@signature-params": ` + reqSigParams(p))
}

func respBase(status int, p RespParams, digest string) []byte {
	errLine := ""
	if p.Error != "" {
		errLine = `"cf-error": ` + p.Error + "\n"
	}
	return []byte(`"@status": ` + strconv.Itoa(status) + "\n" +
		`"content-digest": ` + digest + "\n" + errLine +
		`"@signature-params": ` + respSigParams(p))
}

func sign(key *ecdsa.PrivateKey, base []byte) (string, error) {
	h := sha256.Sum256(base)
	r, ss, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64) // RFC 9421 ecdsa-p256-sha256: fixed-width r || s
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return sigLabel + "=:" + base64.StdEncoding.EncodeToString(sig) + ":", nil
}

func verify(pub *ecdsa.PublicKey, h http.Header, base []byte) error {
	v := h.Get(HeaderSignature)
	if !strings.HasPrefix(v, sigLabel+"=:") || !strings.HasSuffix(v, ":") {
		return fmt.Errorf("%w: malformed signature", ErrSig)
	}
	sig, err := base64.StdEncoding.DecodeString(v[len(sigLabel)+2 : len(v)-1])
	if err != nil {
		return fmt.Errorf("%w: malformed signature", ErrSig)
	}
	if len(sig) != 64 {
		return fmt.Errorf("%w: malformed signature", ErrSig)
	}
	hash := sha256.Sum256(base)
	if !ecdsa.Verify(pub, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return ErrSig
	}
	return nil
}

func checkSkew(created, now time.Time) error {
	if d := now.Sub(created); d > MaxSkew || d < -MaxSkew {
		return ErrStale
	}
	return nil
}

// SignRequest sets Content-Digest, Cf-Ephemeral, Signature-Input and
// Signature on r for body.
func SignRequest(r *http.Request, body []byte, key *ecdsa.PrivateKey, p ReqParams) error {
	if !tokenRe.MatchString(p.Nonce) || !tokenRe.MatchString(p.KeyID) || p.Authority == "" {
		return fmt.Errorf("%w: bad parameters", ErrSig)
	}
	digest := ContentDigest(body)
	sig, err := sign(key, reqBase(r, p, digest))
	if err != nil {
		return err
	}
	r.Header.Set(HeaderContentDigest, digest)
	r.Header.Set(HeaderEphemeral, p.Ephemeral)
	r.Header.Set(HeaderSignatureInput, sigLabel+"="+reqSigParams(p))
	r.Header.Set(HeaderSignature, sig)
	return nil
}

var reqInputRe = regexp.MustCompile(`^sig=\(.*\);created=(\d{1,12});nonce="([^"]*)";keyid="([^"]*)";alg="[^"]*"$`)

// VerifyRequest checks r's signature against authority (the server's own
// expected host, never taken from the request), body and now. lookup maps
// the signed keyid to the signer's public key. It returns the verified
// parameters, whose Authority is the given one.
func VerifyRequest(r *http.Request, body []byte, authority string, now time.Time, lookup func(keyID string) (*ecdsa.PublicKey, error)) (ReqParams, error) {
	m := reqInputRe.FindStringSubmatch(r.Header.Get(HeaderSignatureInput))
	if m == nil {
		return ReqParams{}, fmt.Errorf("%w: malformed signature input", ErrSig)
	}
	sec, _ := strconv.ParseInt(m[1], 10, 64)
	p := ReqParams{Authority: authority, KeyID: m[3], Nonce: m[2], Created: time.Unix(sec, 0), Ephemeral: r.Header.Get(HeaderEphemeral)}
	if !tokenRe.MatchString(p.Nonce) || !tokenRe.MatchString(p.KeyID) ||
		r.Header.Get(HeaderSignatureInput) != sigLabel+"="+reqSigParams(p) {
		return ReqParams{}, fmt.Errorf("%w: non-canonical signature input", ErrSig)
	}
	if err := checkSkew(p.Created, now); err != nil {
		return ReqParams{}, err
	}
	if err := checkDigest(r.Header, body); err != nil {
		return ReqParams{}, err
	}
	pub, err := lookup(p.KeyID)
	if err != nil {
		return ReqParams{}, err
	}
	if err := verify(pub, r.Header, reqBase(r, p, r.Header.Get(HeaderContentDigest))); err != nil {
		return ReqParams{}, err
	}
	return p, nil
}

// SignResponse sets Content-Digest (of body, the ciphertext), Signature-Input
// and Signature on h for a response with the given status.
func SignResponse(h http.Header, status int, body []byte, key *ecdsa.PrivateKey, p RespParams) error {
	if !tokenRe.MatchString(p.ReqNonce) || !tokenRe.MatchString(p.KeyID) || p.Error != "" && !tokenRe.MatchString(p.Error) {
		return fmt.Errorf("%w: bad parameters", ErrSig)
	}
	digest := ContentDigest(body)
	sig, err := sign(key, respBase(status, p, digest))
	if err != nil {
		return err
	}
	if p.Error != "" {
		h.Set(HeaderError, p.Error)
	}
	h.Set(HeaderContentDigest, digest)
	h.Set(HeaderSignatureInput, sigLabel+"="+respSigParams(p))
	h.Set(HeaderSignature, sig)
	return nil
}

var respInputRe = regexp.MustCompile(`^sig=\(.*\);created=(\d{1,12});req-nonce="([^"]*)";keyid="([^"]*)";alg="[^"]*"$`)

// VerifyResponse checks a response's signature with pub. reqNonce is the
// nonce the caller sent, so a response to another request is rejected.
func VerifyResponse(h http.Header, status int, body []byte, reqNonce string, now time.Time, pub *ecdsa.PublicKey) (RespParams, error) {
	m := respInputRe.FindStringSubmatch(h.Get(HeaderSignatureInput))
	if m == nil {
		return RespParams{}, fmt.Errorf("%w: malformed signature input", ErrSig)
	}
	sec, _ := strconv.ParseInt(m[1], 10, 64)
	p := RespParams{KeyID: m[3], ReqNonce: m[2], Created: time.Unix(sec, 0), Error: h.Get(HeaderError)}
	if !tokenRe.MatchString(p.KeyID) || !tokenRe.MatchString(p.ReqNonce) || p.Error != "" && !tokenRe.MatchString(p.Error) ||
		h.Get(HeaderSignatureInput) != sigLabel+"="+respSigParams(p) {
		return RespParams{}, fmt.Errorf("%w: non-canonical signature input", ErrSig)
	}
	if p.ReqNonce != reqNonce {
		return RespParams{}, fmt.Errorf("%w: response is for another request", ErrSig)
	}
	if err := checkSkew(p.Created, now); err != nil {
		return RespParams{}, err
	}
	if err := checkDigest(h, body); err != nil {
		return RespParams{}, err
	}
	if err := verify(pub, h, respBase(status, p, h.Get(HeaderContentDigest))); err != nil {
		return RespParams{}, err
	}
	return p, nil
}
