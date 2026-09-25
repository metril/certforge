package api

import (
	"context"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
)

// This file answers the Phase 3 operations with 501 until their own task
// lands. Every later task deletes the stubs it implements; Task 10 deletes
// this file.

// errNotImplemented answers Phase 3 operations until their task lands.
var errNotImplemented = &HTTPError{Status: http.StatusNotImplemented, Title: "Not implemented", Detail: "This operation arrives later in Phase 3."}

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
func (s *Server) ListAgentCAs(context.Context, gen.ListAgentCAsRequestObject) (gen.ListAgentCAsResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) RotateAgentCA(context.Context, gen.RotateAgentCARequestObject) (gen.RotateAgentCAResponseObject, error) {
	return nil, errNotImplemented
}
func (s *Server) RetireAgentCA(context.Context, gen.RetireAgentCARequestObject) (gen.RetireAgentCAResponseObject, error) {
	return nil, errNotImplemented
}
