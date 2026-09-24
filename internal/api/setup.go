package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/setup"
)

// GetSetupStatus reports whether first-run setup is pending.
func (s *Server) GetSetupStatus(ctx context.Context, _ gen.GetSetupStatusRequestObject) (gen.GetSetupStatusResponseObject, error) {
	needs, err := s.d.Setup.NeedsSetup(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetSetupStatus200JSONResponse(gen.SetupStatus{NeedsSetup: needs}), nil
}

// CompleteSetup runs first-run setup once and logs the admin in.
func (s *Server) CompleteSetup(ctx context.Context, req gen.CompleteSetupRequestObject) (gen.CompleteSetupResponseObject, error) {
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	res, err := s.d.Setup.Complete(ctx, setup.Input{
		AdminPassword: req.Body.AdminPassword,
		OrgName:       req.Body.OrgName,
		OrgSlug:       req.Body.OrgSlug,
		BaseURL:       req.Body.BaseUrl,
	})
	switch {
	case errors.Is(err, setup.ErrAlreadyComplete):
		return nil, &HTTPError{Status: http.StatusConflict, Title: "Setup already completed"}
	case errors.Is(err, setup.ErrInvalid):
		return nil, &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid setup input", Detail: err.Error()}
	case errors.Is(err, authn.ErrBusy):
		writeRetryAfter(ctx, "1")
		return nil, errTooBusy
	case err != nil:
		return nil, err
	}
	me, err := s.startSession(ctx, res.AdminID)
	if err != nil {
		return nil, err
	}
	return gen.CompleteSetup200JSONResponse(me), nil
}
