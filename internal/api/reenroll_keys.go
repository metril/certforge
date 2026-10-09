package api

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

// requireKeysExportIfKeyGrants requires keys:export to re-enrol a client
// that holds a live grant delivering a private key (a key-bearing layout or
// any agent deploy target): the fresh enrolment token lets a new agent pull
// that key from the grant bundle, which clients:write alone must not allow.
func (s *Server) requireKeysExportIfKeyGrants(ctx context.Context, orgID, clientID uuid.UUID) error {
	views, err := s.queries().GrantViews(ctx, sqlcgen.GrantViewsParams{OrgID: orgID, ClientID: &clientID})
	if err != nil || len(views) == 0 {
		return err
	}
	ids := make([]uuid.UUID, len(views))
	for i, v := range views {
		ids[i] = v.ID
	}
	rows, err := s.queries().GrantSources(ctx, ids)
	if err != nil {
		return err
	}
	for _, r := range rows {
		needs := r.TargetType != nil
		if !needs && len(r.LayoutFiles) > 0 {
			var files []delivery.OutputFile
			if err := json.Unmarshal(r.LayoutFiles, &files); err != nil {
				return err
			}
			needs = delivery.NeedsKey(files)
		}
		if needs {
			_, err := authorize(ctx, authz.ActionKeysExport, &orgID)
			return err
		}
	}
	return nil
}
