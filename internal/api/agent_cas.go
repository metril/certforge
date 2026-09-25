package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
)

func agentCAOut(i agentca.Info) gen.AgentCA {
	return gen.AgentCA{Id: i.ID, Status: gen.AgentCAStatus(i.Status), Fingerprint: agentca.Fingerprint(i.Cert.Raw),
		Subject: i.Cert.Subject.CommonName, NotBefore: i.Cert.NotBefore, NotAfter: i.Cert.NotAfter,
		ActiveClientCerts: int(i.ActiveClientCerts), CreatedAt: i.CreatedAt}
}

func (s *Server) agentCA(ctx context.Context, id uuid.UUID) (gen.AgentCA, error) {
	infos, err := s.d.Agents.CA.List(ctx)
	if err != nil {
		return gen.AgentCA{}, err
	}
	for _, i := range infos {
		if i.ID == id {
			return agentCAOut(i), nil
		}
	}
	return gen.AgentCA{}, notFound("agent CA %s", id)
}

// ListAgentCAs returns every agent CA and the listener certificate.
func (s *Server) ListAgentCAs(ctx context.Context, _ gen.ListAgentCAsRequestObject) (gen.ListAgentCAsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsRead, nil); err != nil {
		return nil, err
	}
	infos, err := s.d.Agents.CA.List(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.AgentCAList{Items: make([]gen.AgentCA, 0, len(infos)), Listener: gen.AgentListener{Names: []string{}}}
	for _, i := range infos {
		out.Items = append(out.Items, agentCAOut(i))
	}
	if s.d.AgentListener != nil {
		if info, ok := s.d.AgentListener.Info(); ok {
			out.Listener = gen.AgentListener{CaId: &info.CAID, Names: info.Names, NotAfter: &info.NotAfter}
		}
	}
	return gen.ListAgentCAs200JSONResponse(out), nil
}

// RotateAgentCA creates a new active agent CA.
func (s *Server) RotateAgentCA(ctx context.Context, _ gen.RotateAgentCARequestObject) (gen.RotateAgentCAResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsWrite, nil); err != nil {
		return nil, err
	}
	ca, err := s.d.Agents.RotateCA(ctx)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	out, err := s.agentCA(ctx, ca.ID)
	if err != nil {
		return nil, err
	}
	return gen.RotateAgentCA201JSONResponse(out), nil
}

// RetireAgentCA stops trusting a retiring agent CA.
func (s *Server) RetireAgentCA(ctx context.Context, r gen.RetireAgentCARequestObject) (gen.RetireAgentCAResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsWrite, nil); err != nil {
		return nil, err
	}
	if err := s.d.Agents.RetireCA(ctx, r.Id); err != nil {
		return nil, mapAgentErr(err)
	}
	out, err := s.agentCA(ctx, r.Id)
	if err != nil {
		return nil, err
	}
	return gen.RetireAgentCA200JSONResponse(out), nil
}
