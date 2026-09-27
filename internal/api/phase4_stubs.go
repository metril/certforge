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

// UploadCertificate lands in Task 13 (upload and unmanaged certificates).
func (s *Server) UploadCertificate(_ context.Context, _ gen.UploadCertificateRequestObject) (gen.UploadCertificateResponseObject, error) {
	return nil, notImplemented
}

// UploadCertificateVersion lands in Task 13 (upload and unmanaged certificates).
func (s *Server) UploadCertificateVersion(_ context.Context, _ gen.UploadCertificateVersionRequestObject) (gen.UploadCertificateVersionResponseObject, error) {
	return nil, notImplemented
}

// GetRateLedger lands in Task 11 (rate ledger).
func (s *Server) GetRateLedger(_ context.Context, _ gen.GetRateLedgerRequestObject) (gen.GetRateLedgerResponseObject, error) {
	return nil, notImplemented
}
