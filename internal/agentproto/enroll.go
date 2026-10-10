package agentproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Enrolment is a one-off exchange that needs no session and no client
// certificate, and gives a hostile proxy nothing to forge or read:
//
//  1. GET PathEnrollHello?nonce=N returns EnrollHello: a fresh server
//     ephemeral key, signed by the responder and bound to N. The agent
//     verifies the signature chain against the CA fingerprint in its token.
//  2. POST PathEnroll with HeaderEnrollHello set carries EnrollSubmit,
//     HPKE-sealed to that ephemeral key. Its Pop is an HMAC keyed by the
//     token's hash, so only a holder of the token can produce one, and it
//     covers the CSR, so the body cannot be re-used with another key. The
//     reply (EnrollAccepted, or a problem) is sealed to Reply and signed.
//  3. POST PathEnroll/{id} polls with EnrollPollRequest, signed by the CSR
//     key, until an administrator approves; the signed reply is sealed to a
//     fresh agent ephemeral key and, once approved, carries the certificate.
const (
	PathEnroll        = "/agent/v1/enroll"
	PathEnrollHello   = "/agent/v1/enroll/hello"
	HeaderEnrollHello = "Cf-Enroll-Hello"

	popLabel    = "cf-enrol-v1"
	lookupLabel = "cf-enrol-id"

	// Poll statuses.
	EnrollPending  = "pending"
	EnrollApproved = "approved"
	EnrollRejected = "rejected"
	EnrollExpired  = "expired"
)

// EnrollHello is the body of GET PathEnrollHello.
type EnrollHello struct {
	ID        string   `json:"id"`        // base64url, names the ephemeral key; the HPKE info nonce
	Ephemeral string   `json:"ephemeral"` // base64 X9.62 uncompressed P-256
	Chain     []string `json:"chain"`     // base64 DER of the CA certificate(s) above the responder leaf
	ExpiresIn int      `json:"expiresIn"`
}

// EnrollSubmit is the sealed plaintext of POST PathEnroll.
type EnrollSubmit struct {
	LookupID string `json:"lookupId"`
	CSR      string `json:"csr"` // PEM CERTIFICATE REQUEST
	Facts    Facts  `json:"facts"`
	Created  int64  `json:"created"` // unix seconds
	Nonce    string `json:"nonce"`
	Reply    string `json:"reply"` // base64 X9.62 P-256 key the reply is sealed to
	Pop      string `json:"pop"`
}

// EnrollAccepted answers a verified EnrollSubmit.
type EnrollAccepted struct {
	ID         uuid.UUID `json:"id"`
	PollSecret string    `json:"pollSecret"`
	VerifyCode string    `json:"verifyCode"`
	Status     string    `json:"status"` // pending, or approved when approval is off
	ExpiresAt  time.Time `json:"expiresAt"`
}

// EnrollPollRequest is the body of a poll.
type EnrollPollRequest struct {
	PollSecret string `json:"pollSecret"`
}

// EnrollPoll answers a poll. Certificate and TrustBundle are set once
// approved.
type EnrollPoll struct {
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Certificate string    `json:"certificate,omitempty"` // PEM
	TrustBundle string    `json:"trustBundle,omitempty"` // PEM, every trusted agent CA
	AgentURL    string    `json:"agentUrl,omitempty"`
	ClientID    uuid.UUID `json:"clientId,omitempty"`
}

// LookupIDBytes names a token without revealing it: sha256 of
// "cf-enrol-id" || tokenHash. It is stored indexed beside the token.
func LookupIDBytes(tokenHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte(lookupLabel))
	h.Write(tokenHash)
	return h.Sum(nil)
}

// LookupID is LookupIDBytes as the base64url string that goes on the wire.
func LookupID(tokenHash []byte) string {
	return base64.RawURLEncoding.EncodeToString(LookupIDBytes(tokenHash))
}

// CSRDER returns the DER of a PEM certificate request.
func CSRDER(csrPEM string) ([]byte, error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("agentproto: not a PEM certificate request")
	}
	return blk.Bytes, nil
}

// EnrollPop proves possession of the token: HMAC-SHA256 keyed by the token's
// hash over label, sha256 of the CSR's DER, the @authority the agent dials,
// created, the nonce and the reply key (so a substituted reply key fails too).
func EnrollPop(tokenHash, csrDER []byte, host string, created int64, nonce, reply string) string {
	d := sha256.Sum256(csrDER)
	m := hmac.New(sha256.New, tokenHash)
	for _, p := range [][]byte{[]byte(popLabel), d[:], []byte(host), []byte(strconv.FormatInt(created, 10)), []byte(nonce), []byte(reply)} {
		m.Write(p)
		m.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// VerifyPop reports whether pop is EnrollPop's value for the same inputs.
func VerifyPop(pop string, tokenHash, csrDER []byte, host string, created int64, nonce, reply string) bool {
	want := EnrollPop(tokenHash, csrDER, host, created, nonce, reply)
	return subtle.ConstantTimeCompare([]byte(pop), []byte(want)) == 1
}

// VerifyCode is the short code an administrator compares with the one the
// agent logs: base32(sha256(public key DER || CA fingerprint))[:8]. A proxy
// that substitutes either key or CA changes it.
func VerifyCode(pubDER []byte, caFingerprint string) string {
	h := sha256.New()
	h.Write(pubDER)
	h.Write([]byte(caFingerprint))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil))[:8]
}

// FormatVerifyCode groups a code for display: ABCD-EFGH.
func FormatVerifyCode(c string) string {
	if len(c) == 8 {
		return strings.ToUpper(c[:4] + "-" + c[4:])
	}
	return c
}
