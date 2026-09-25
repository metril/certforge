package api

import (
	"context"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
)

// This file answers the Phase 3 operations with 501 until their own task
// lands. Every later task deletes the stubs it implements; Task 10 deletes
// this file.
//
// errNotImplemented answers Phase 3 operations until their task lands.
var errNotImplemented = &HTTPError{Status: http.StatusNotImplemented, Title: "Not implemented", Detail: "This operation arrives later in Phase 3."}

func (s *Server) ListClients(context.Context, gen.ListClientsRequestObject) (gen.ListClientsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) CreateClient(context.Context, gen.CreateClientRequestObject) (gen.CreateClientResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ListAllClients(context.Context, gen.ListAllClientsRequestObject) (gen.ListAllClientsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) GetClient(context.Context, gen.GetClientRequestObject) (gen.GetClientResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) UpdateClient(context.Context, gen.UpdateClientRequestObject) (gen.UpdateClientResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) DeleteClient(context.Context, gen.DeleteClientRequestObject) (gen.DeleteClientResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) RevokeClient(context.Context, gen.RevokeClientRequestObject) (gen.RevokeClientResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ReenrollClient(context.Context, gen.ReenrollClientRequestObject) (gen.ReenrollClientResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ListClientGrants(context.Context, gen.ListClientGrantsRequestObject) (gen.ListClientGrantsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) CreateGrant(context.Context, gen.CreateGrantRequestObject) (gen.CreateGrantResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) UpdateGrant(context.Context, gen.UpdateGrantRequestObject) (gen.UpdateGrantResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) DeleteGrant(context.Context, gen.DeleteGrantRequestObject) (gen.DeleteGrantResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) RedeployGrant(context.Context, gen.RedeployGrantRequestObject) (gen.RedeployGrantResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ListClientHookRuns(context.Context, gen.ListClientHookRunsRequestObject) (gen.ListClientHookRunsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ListCertificateDeployments(context.Context, gen.ListCertificateDeploymentsRequestObject) (gen.ListCertificateDeploymentsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ListLayouts(context.Context, gen.ListLayoutsRequestObject) (gen.ListLayoutsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) CreateLayout(context.Context, gen.CreateLayoutRequestObject) (gen.CreateLayoutResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) GetLayout(context.Context, gen.GetLayoutRequestObject) (gen.GetLayoutResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) UpdateLayout(context.Context, gen.UpdateLayoutRequestObject) (gen.UpdateLayoutResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) DeleteLayout(context.Context, gen.DeleteLayoutRequestObject) (gen.DeleteLayoutResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ListDeployTargets(context.Context, gen.ListDeployTargetsRequestObject) (gen.ListDeployTargetsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) CreateDeployTarget(context.Context, gen.CreateDeployTargetRequestObject) (gen.CreateDeployTargetResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) GetDeployTarget(context.Context, gen.GetDeployTargetRequestObject) (gen.GetDeployTargetResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) UpdateDeployTarget(context.Context, gen.UpdateDeployTargetRequestObject) (gen.UpdateDeployTargetResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) DeleteDeployTarget(context.Context, gen.DeleteDeployTargetRequestObject) (gen.DeleteDeployTargetResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ListHooks(context.Context, gen.ListHooksRequestObject) (gen.ListHooksResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) CreateHook(context.Context, gen.CreateHookRequestObject) (gen.CreateHookResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) GetHook(context.Context, gen.GetHookRequestObject) (gen.GetHookResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) UpdateHook(context.Context, gen.UpdateHookRequestObject) (gen.UpdateHookResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) DeleteHook(context.Context, gen.DeleteHookRequestObject) (gen.DeleteHookResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) ListAgentCAs(context.Context, gen.ListAgentCAsRequestObject) (gen.ListAgentCAsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) RotateAgentCA(context.Context, gen.RotateAgentCARequestObject) (gen.RotateAgentCAResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) RetireAgentCA(context.Context, gen.RetireAgentCARequestObject) (gen.RetireAgentCAResponseObject, error) {
	return nil, errNotImplemented
}
