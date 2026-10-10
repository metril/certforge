package agentproto

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Message types on the agent WebSocket.
const (
	TypeHello             = "hello"
	TypeHelloAck          = "hello_ack"
	TypeWelcome           = "welcome"
	TypeSync              = "sync"
	TypeTrustBundleUpdate = "trust_bundle_update"
	TypeRevoked           = "revoked"
	TypeHeartbeat         = "heartbeat"
	TypeDeployResult      = "deploy_result"
	TypeChallengePresent  = "challenge_present"
	TypeChallengeCleanup  = "challenge_cleanup"
	TypeChallengeReady    = "challenge_ready"
)

// WebSocket close codes the server uses (4000-4999 are application codes).
const (
	CloseReplaced = 4000 // a newer connection for the same client took over
	CloseRevoked  = 4001 // the client was revoked or re-enrolled
	CloseIdle     = 4002 // no message or pong within the idle timeout
	CloseRekey    = 4003 // the session's message limit is near: reconnect for fresh keys
)

// Deployment result states an agent reports.
const (
	StateOK     = "ok"
	StateFailed = "failed"
)

// Message is one WebSocket message; MsgType is its "type" field.
type Message interface{ MsgType() string }

// ErrUnknownType is returned by Unmarshal for an unrecognised "type".
var ErrUnknownType = errors.New("agentproto: unknown message type")

// Hello is the agent's first message on a new socket.
type Hello struct {
	AgentVersion string   `json:"agentVersion"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Capabilities []string `json:"capabilities"`
}

// HelloAck is the first frame of a socket, the only one sent in the clear:
// the server's ephemeral key, the session id (the HKDF salt) and the responder
// certificate chain (base64 DER, leaf first), signed by the responder over
// both ephemeral keys, the session id and the upgrade request's nonce (see
// SignHelloAck). Every frame after it is sealed under the session it opens.
type HelloAck struct {
	Ephemeral      string   `json:"ephemeral"`
	Session        string   `json:"session"`
	Chain          []string `json:"chain"`
	SignatureInput string   `json:"signatureInput"`
	Signature      string   `json:"signature"`
}

// Welcome answers Hello (inside the sealed channel) with the heartbeat
// interval and desired revision.
type Welcome struct {
	HeartbeatSeconds int   `json:"heartbeatSeconds"`
	Revision         int64 `json:"revision"`
}

// Sync tells the agent its desired revision changed.
type Sync struct {
	Revision int64 `json:"revision"`
}

// TrustBundleUpdate carries every trusted agent CA as PEM after a rotation.
type TrustBundleUpdate struct {
	Bundle string `json:"bundle"`
}

// Revoked precedes a close with CloseRevoked.
type Revoked struct{}

// Heartbeat reports what is installed; the server compares it for drift.
type Heartbeat struct {
	Installed []InstalledFile `json:"installed"`
}

// DeployResult is a Report sent over the socket.
type DeployResult struct {
	Report
}

// ChallengePresent asks a client's agent to serve an http-01 or
// tls-alpn-01 challenge: publish keyAuth at the http-01 well-known path (or
// under webroot, when set) or in a tls-alpn-01 self-signed certificate for
// domain. Method is "http-01" or "tls-alpn-01".
type ChallengePresent struct {
	Token   string `json:"token"`
	KeyAuth string `json:"keyAuth"`
	Domain  string `json:"domain"`
	Method  string `json:"method"`
	Webroot string `json:"webroot,omitempty"`
}

// ChallengeCleanup asks the agent to stop serving token.
type ChallengeCleanup struct {
	Token string `json:"token"`
}

// ChallengeReady is the agent's reply to ChallengePresent; Error is set
// when the agent could not serve the challenge.
type ChallengeReady struct {
	Token string `json:"token"`
	Error string `json:"error,omitempty"`
}

// MsgType implementations.
func (Hello) MsgType() string             { return TypeHello }
func (HelloAck) MsgType() string          { return TypeHelloAck }
func (Welcome) MsgType() string           { return TypeWelcome }
func (Sync) MsgType() string              { return TypeSync }
func (TrustBundleUpdate) MsgType() string { return TypeTrustBundleUpdate }
func (Revoked) MsgType() string           { return TypeRevoked }
func (Heartbeat) MsgType() string         { return TypeHeartbeat }
func (DeployResult) MsgType() string      { return TypeDeployResult }
func (ChallengePresent) MsgType() string  { return TypeChallengePresent }
func (ChallengeCleanup) MsgType() string  { return TypeChallengeCleanup }
func (ChallengeReady) MsgType() string    { return TypeChallengeReady }

// Marshal encodes m as one JSON object with a leading "type" field.
func Marshal(m Message) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("agentproto: %w", err)
	}
	if len(body) < 2 || body[0] != '{' {
		return nil, fmt.Errorf("agentproto: %T is not a JSON object", m)
	}
	t, _ := json.Marshal(m.MsgType())
	out := make([]byte, 0, len(body)+len(t)+9)
	out = append(out, `{"type":`...)
	out = append(out, t...)
	if len(body) > 2 {
		out = append(out, ',')
	}
	return append(out, body[1:]...), nil
}

// Unmarshal decodes one message by its "type" field.
func Unmarshal(b []byte) (Message, error) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("agentproto: %w", err)
	}
	switch head.Type {
	case TypeHello:
		return decode[Hello](b)
	case TypeHelloAck:
		return decode[HelloAck](b)
	case TypeWelcome:
		return decode[Welcome](b)
	case TypeSync:
		return decode[Sync](b)
	case TypeTrustBundleUpdate:
		return decode[TrustBundleUpdate](b)
	case TypeRevoked:
		return decode[Revoked](b)
	case TypeHeartbeat:
		return decode[Heartbeat](b)
	case TypeDeployResult:
		return decode[DeployResult](b)
	case TypeChallengePresent:
		return decode[ChallengePresent](b)
	case TypeChallengeCleanup:
		return decode[ChallengeCleanup](b)
	case TypeChallengeReady:
		return decode[ChallengeReady](b)
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownType, head.Type)
}

func decode[T Message](b []byte) (Message, error) {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("agentproto: %w", err)
	}
	return v, nil
}
