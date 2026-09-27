package agents

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

type leafKey struct{}

// WithLeaf attaches the agent's verified leaf certificate to ctx. The agent
// listener does this once, when it accepts the socket; OnMessage re-runs
// Authenticate on it for every message on the connection's long lifetime,
// not only at connect, so a certificate replaced by a renew or a
// revoke-then-reenroll is refused mid-socket exactly as a fresh REST
// request already is (requireAgent re-authenticates every request).
func WithLeaf(ctx context.Context, leaf *x509.Certificate) context.Context {
	return context.WithValue(ctx, leafKey{}, leaf)
}

func leafFrom(ctx context.Context) *x509.Certificate {
	leaf, _ := ctx.Value(leafKey{}).(*x509.Certificate)
	return leaf
}

// OnMessage implements agenthub.Handler: the socket carries the same
// heartbeat and report the REST endpoints accept, plus hello.
func (s *Service) OnMessage(ctx context.Context, clientID uuid.UUID, m agentproto.Message) ([]agentproto.Message, error) {
	leaf := leafFrom(ctx)
	if leaf == nil {
		return nil, unauthorized("client %s: no verified agent certificate on this connection", clientID)
	}
	c, err := s.Authenticate(ctx, leaf)
	if err != nil {
		return nil, err
	}
	if c.ID != clientID {
		return nil, unauthorized("client %s: certificate belongs to a different client", clientID)
	}
	switch v := m.(type) {
	case agentproto.Hello:
		ack, err := s.Hello(ctx, c, v)
		if err != nil {
			return nil, err
		}
		return []agentproto.Message{ack}, nil
	case agentproto.Heartbeat:
		return nil, s.Heartbeat(ctx, c, v)
	case agentproto.DeployResult:
		return nil, s.Report(ctx, c, v.Report)
	case agentproto.ChallengeReady:
		return nil, s.ChallengeReady(ctx, c.ID, v)
	}
	return nil, fmt.Errorf("agents: agents do not send %s messages", m.MsgType())
}

// Hello records the agent's facts and answers with the heartbeat interval
// and the client's desired revision.
func (s *Service) Hello(ctx context.Context, c sqlcgen.Client, h agentproto.Hello) (agentproto.HelloAck, error) {
	caps := make([]string, 0, len(h.Capabilities))
	for i, x := range h.Capabilities {
		if i == 32 {
			break
		}
		caps = append(caps, clip(x, 64))
	}
	nc, err := s.Q.UpdateClientFacts(ctx, sqlcgen.UpdateClientFactsParams{ID: c.ID, Hostname: clip(h.Hostname, 253),
		Os: clip(h.OS, 32), Arch: clip(h.Arch, 32), AgentVersion: clip(h.AgentVersion, 64), Capabilities: caps})
	if err != nil {
		return agentproto.HelloAck{}, err
	}
	return agentproto.HelloAck{HeartbeatSeconds: s.CurrentSettings(ctx).HeartbeatSeconds, Revision: nc.DesiredRevision}, nil
}
