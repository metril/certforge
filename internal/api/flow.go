package api

import (
	"context"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
)

// GetFlow is implemented in the next commit.
func (s *Server) GetFlow(_ context.Context, _ gen.GetFlowRequestObject) (gen.GetFlowResponseObject, error) {
	return nil, &HTTPError{Status: http.StatusServiceUnavailable, Title: "Service Unavailable", Detail: "flow is not available yet"}
}
