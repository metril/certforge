package api

import (
	"context"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
)

// GetServerInfo returns the running server's version (Shared contract, R7
// Deviation). Any authenticated principal may call it: it checks only that
// a principal exists, not any authz.Action, the same pattern as GetMe.
func (s *Server) GetServerInfo(ctx context.Context, _ gen.GetServerInfoRequestObject) (gen.GetServerInfoResponseObject, error) {
	if _, ok := authn.PrincipalFrom(ctx); !ok {
		return nil, errUnauthenticated
	}
	return gen.GetServerInfo200JSONResponse{Version: s.d.Version}, nil
}
