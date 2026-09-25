package agents

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// OnMessage implements agenthub.Handler: the socket carries the same
// heartbeat and report the REST endpoints accept, plus hello.
func (s *Service) OnMessage(ctx context.Context, clientID uuid.UUID, m agentproto.Message) ([]agentproto.Message, error) {
	c, err := s.Q.GetClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if c.Status != "active" {
		return nil, unauthorized("client %s is %s", clientID, c.Status)
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
