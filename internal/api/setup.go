package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
	return gen.GetSetupStatus200JSONResponse(gen.SetupStatus{NeedsSetup: needs, TokenRequired: s.d.Config.SetupToken != ""}), nil
}

// CompleteSetup runs first-run setup once and logs the admin in.
func (s *Server) CompleteSetup(ctx context.Context, req gen.CompleteSetupRequestObject) (gen.CompleteSetupResponseObject, error) {
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	// Checked before any setup work so a wrong token cannot probe state.
	if want := s.d.Config.SetupToken; want != "" {
		given := ""
		if req.Body.SetupToken != nil {
			given = *req.Body.SetupToken
		}
		a, b := sha256.Sum256([]byte(given)), sha256.Sum256([]byte(want))
		if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			s.d.Log.Warn("setup rejected: setup token missing or wrong")
			return nil, &HTTPError{Status: http.StatusUnauthorized, Title: "Setup token required or invalid"}
		}
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
		// Setup has committed (a retry would get 409) and the admin exists, so
		// tell the user to log in rather than answering with a bare 500.
		s.d.Log.Error("setup completed but the session could not be started", "err", err)
		return nil, &HTTPError{Status: http.StatusConflict, Title: "Setup completed",
			Detail: "Setup completed but signing you in failed. Log in with the admin password you just set."}
	}
	return gen.CompleteSetup200JSONResponse(me), nil
}
