package api

import (
	"context"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
)

// notImplemented is the stub response for a Phase 4A operation whose
// contract is in api/openapi.yaml but whose handler lands in a later task.
var notImplemented = &HTTPError{Status: http.StatusNotImplemented, Title: "Not implemented"}

// ImportCertificates lands in Task 14 (import from acme.sh and certbot).
func (s *Server) ImportCertificates(_ context.Context, _ gen.ImportCertificatesRequestObject) (gen.ImportCertificatesResponseObject, error) {
	return nil, notImplemented
}
