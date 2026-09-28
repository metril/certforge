package api

import (
	"context"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
)

// Phase 5A contract stubs. These operations are declared in
// api/openapi.yaml (Task 2) but not yet implemented; each later task
// (10/11: CreateServerGrant/ListTargetGrants) moves its own method out of
// this file into its resource file and, once the last one leaves
// (Task 13), this file is deleted.
// GetKeysStatus/StartRewrap moved to internal/api/keys.go (Task 5);
// RotateCa moved to internal/api/issuers.go and RevokeCertificateVersion
// to internal/api/certificates.go (Task 7); TestVaultSettings moved to
// internal/api/settings.go (Task 8).

var errNotImplemented = &HTTPError{Status: http.StatusNotImplemented, Title: "Not implemented"}

// CreateServerGrant is implemented in Task 11 (client-less grants and dispatcher).
func (s *Server) CreateServerGrant(context.Context, gen.CreateServerGrantRequestObject) (gen.CreateServerGrantResponseObject, error) {
	return nil, errNotImplemented
}

// ListTargetGrants is implemented in Task 11 (client-less grants and dispatcher).
func (s *Server) ListTargetGrants(context.Context, gen.ListTargetGrantsRequestObject) (gen.ListTargetGrantsResponseObject, error) {
	return nil, errNotImplemented
}
