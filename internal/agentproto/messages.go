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
	TypeSync              = "sync"
	TypeTrustBundleUpdate = "trust_bundle_update"
	TypeRevoked           = "revoked"
	TypeHeartbeat         = "heartbeat"
	TypeDeployResult      = "deploy_result"
)

// WebSocket close codes the server uses (4000-4999 are application codes).
const (
	CloseReplaced = 4000 // a newer connection for the same client took over
	CloseRevoked  = 4001 // the client was revoked or re-enrolled
	CloseIdle     = 4002 // no message or pong within the idle timeout
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

// HelloAck answers Hello with the heartbeat interval and desired revision.
type HelloAck struct {
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

// MsgType implementations.
func (Hello) MsgType() string             { return TypeHello }
func (HelloAck) MsgType() string          { return TypeHelloAck }
func (Sync) MsgType() string              { return TypeSync }
func (TrustBundleUpdate) MsgType() string { return TypeTrustBundleUpdate }
func (Revoked) MsgType() string           { return TypeRevoked }
func (Heartbeat) MsgType() string         { return TypeHeartbeat }
func (DeployResult) MsgType() string      { return TypeDeployResult }

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
