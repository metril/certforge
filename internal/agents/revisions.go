package agents

import (
	"context"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func uniq(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]bool, len(ids))
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// bump raises desired_revision of every client in ids inside the caller's
// transaction; nudge must run after that transaction commits.
func (s *Service) bump(ctx context.Context, q *sqlcgen.Queries, ids []uuid.UUID) ([]sqlcgen.BumpClientRevisionsRow, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return q.BumpClientRevisions(ctx, uniq(ids))
}

// nudge sends sync to each bumped client that has a push grant among the
// changed ones. A change that touches only pull grants never nudges: those
// wait for the agent's own pull schedule. Missed nudges are harmless: agents
// reconcile to the latest revision on every connect.
func (s *Service) nudge(revs []sqlcgen.BumpClientRevisionsRow, push map[uuid.UUID]bool) {
	if s.Hub == nil {
		return
	}
	for _, r := range revs {
		if push[r.ID] {
			s.Hub.Send(r.ID, agentproto.Sync{Revision: r.DesiredRevision})
		}
	}
}
