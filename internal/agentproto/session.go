package agentproto

import (
	"net/url"
	"strconv"
	"strings"
)

// Session protocol constants. Requests inside a session carry the session id
// in Cf-Ephemeral (a signed header), so the signature binds the session.
const (
	PathSession = "/agent/v1/session"

	HeaderAgentCert  = "Cf-Agent-Cert"  // handshake only: base64 DER of the agent certificate
	HeaderSignerCert = "Cf-Signer-Cert" // base64 DER of the responder certificate
	HeaderSeq        = "Cf-Seq"         // seq the body was sealed under
	HeaderError      = "Cf-Error"       // machine-readable code on a signed, unsealed refusal

	ErrCodeSession = "session" // unknown or expired session: handshake again
	ErrCodeAuth    = "auth"
	ErrCodeReplay  = "replay"
	ErrCodeStale   = "stale"

	// SessionTTLSeconds is how long a session lives, at most.
	SessionTTLSeconds = 600
)

// SessionResponse is the body of POST /agent/v1/session: the session id and
// the server's ephemeral key (base64 X9.62 uncompressed). The id is also the
// HKDF salt of the session keys.
type SessionResponse struct {
	Session   string `json:"session"`
	Ephemeral string `json:"ephemeral"`
	ExpiresIn int    `json:"expiresIn"`
}

// Authority is the canonical @authority of a URL: lower-case host with the
// default https port dropped.
func Authority(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Host), ":443")
}

// ReqExtra is the AAD binding a sealed request to its session, nonce and target.
func ReqExtra(session, nonce, method, requestURI string) []byte {
	return []byte("req\x00" + session + "\x00" + nonce + "\x00" + method + "\x00" + requestURI)
}

// RespExtra is the AAD binding a sealed response to its request and status.
func RespExtra(session, reqNonce string, status int) []byte {
	return []byte("resp\x00" + session + "\x00" + reqNonce + "\x00" + strconv.Itoa(status))
}
