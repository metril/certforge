package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

type hookRunCursor struct {
	RanAt time.Time `json:"ranAt"`
	ID    uuid.UUID `json:"id"`
}

// ListClientHookRuns returns one page of a client's hook runs, newest first.
func (s *Server) ListClientHookRuns(ctx context.Context, r gen.ListClientHookRunsRequestObject) (gen.ListClientHookRunsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsRead, &r.OrgId); err != nil {
		return nil, err
	}
	q := s.queries()
	if _, err := q.GetClient(ctx, sqlcgen.GetClientParams{ID: r.Id, OrgID: r.OrgId}); errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("client %s", r.Id)
	} else if err != nil {
		return nil, err
	}
	limit := 50
	if r.Params.Limit != nil {
		if *r.Params.Limit < 1 || *r.Params.Limit > 500 {
			return nil, unprocessable("limit", "limit must be 1 to 500")
		}
		limit = *r.Params.Limit
	}
	arg := sqlcgen.ListHookRunsParams{ClientID: r.Id, PageLimit: int32(limit + 1)}
	if r.Params.Cursor != nil && *r.Params.Cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(*r.Params.Cursor)
		var c hookRunCursor
		if err != nil || json.Unmarshal(b, &c) != nil || c.ID == uuid.Nil {
			return nil, unprocessable("cursor", "cursor is not from this list")
		}
		arg.HasCursor, arg.BeforeTs, arg.BeforeID = true, c.RanAt, c.ID
	}
	rows, err := q.ListHookRuns(ctx, arg)
	if err != nil {
		return nil, err
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		b, _ := json.Marshal(hookRunCursor{RanAt: last.RanAt, ID: last.ID})
		n := base64.RawURLEncoding.EncodeToString(b)
		next = &n
	}
	items := make([]gen.HookRun, 0, len(rows))
	for _, x := range rows {
		items = append(items, gen.HookRun{Id: x.ID, GrantId: x.GrantID, HookId: x.HookID, HookName: x.HookName,
			Phase: gen.HookPhase(x.Phase), Argv: x.Argv, ExitCode: int(x.ExitCode), DurationMs: x.DurationMs,
			Stdout: x.Stdout, Stderr: x.Stderr, RanAt: x.RanAt})
	}
	return gen.ListClientHookRuns200JSONResponse(gen.HookRunList{Items: items, NextCursor: next}), nil
}
