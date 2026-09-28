package api

import (
	"context"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
)

// Phase 5A contract stubs. These seven operations are declared in
// api/openapi.yaml (Task 2) but not yet implemented; each later task
// (7: RotateCa, 8: TestVaultSettings, 9: RevokeCertificateVersion,
// 10/11: CreateServerGrant/ListTargetGrants, 5: GetKeysStatus/StartRewrap)
// moves its own method out of this file into its resource file and, once
// the last one leaves (Task 13), this file is deleted.

var errNotImplemented = &HTTPError{Status: http.StatusNotImplemented, Title: "Not implemented"}

// RotateCa is implemented in Task 7 (localca CA lifecycle).
func (s *Server) RotateCa(context.Context, gen.RotateCaRequestObject) (gen.RotateCaResponseObject, error) {
	return nil, errNotImplemented
}

// RevokeCertificateVersion is implemented in Task 7 (localca CA lifecycle, CRL, revocation).
func (s *Server) RevokeCertificateVersion(context.Context, gen.RevokeCertificateVersionRequestObject) (gen.RevokeCertificateVersionResponseObject, error) {
	return nil, errNotImplemented
}

// GetKeysStatus is implemented in Task 5 (multi-wrapper envelope, rewrap, keys API).
func (s *Server) GetKeysStatus(context.Context, gen.GetKeysStatusRequestObject) (gen.GetKeysStatusResponseObject, error) {
	return nil, errNotImplemented
}

// StartRewrap is implemented in Task 5 (multi-wrapper envelope, rewrap, keys API).
func (s *Server) StartRewrap(context.Context, gen.StartRewrapRequestObject) (gen.StartRewrapResponseObject, error) {
	return nil, errNotImplemented
}

// TestVaultSettings is implemented in Task 8 (Vault provider, test endpoint, vaultpki).
func (s *Server) TestVaultSettings(context.Context, gen.TestVaultSettingsRequestObject) (gen.TestVaultSettingsResponseObject, error) {
	return nil, errNotImplemented
}

// CreateServerGrant is implemented in Task 11 (client-less grants and dispatcher).
func (s *Server) CreateServerGrant(context.Context, gen.CreateServerGrantRequestObject) (gen.CreateServerGrantResponseObject, error) {
	return nil, errNotImplemented
}

// ListTargetGrants is implemented in Task 11 (client-less grants and dispatcher).
func (s *Server) ListTargetGrants(context.Context, gen.ListTargetGrantsRequestObject) (gen.ListTargetGrantsResponseObject, error) {
	return nil, errNotImplemented
}
