package main

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/audit"
)

// auditMigratedStepRemovals reports the grant steps migration 00040 dropped
// (an action that named another target): one audit event and one warning per
// row, then the row is deleted. A row whose audit write fails stays for the
// next start.
func auditMigratedStepRemovals(ctx context.Context, pool *pgxpool.Pool, aud *audit.Auditor, log *slog.Logger) error {
	rows, err := pool.Query(ctx, `SELECT r.grant_id, r.action_id, r.old_target_id, r.reason, c.org_id, c.name, a.name
		FROM migrated_step_removals r
		LEFT JOIN client_cert_grants g ON g.id = r.grant_id
		LEFT JOIN certificates c ON c.id = g.cert_id
		LEFT JOIN actions a ON a.id = r.action_id
		ORDER BY r.created_at, r.grant_id`)
	if err != nil {
		return err
	}
	type rec struct {
		grant, action uuid.UUID
		oldTarget     *uuid.UUID
		reason        string
		org           *uuid.UUID
		cert, name    *string
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.grant, &r.action, &r.oldTarget, &r.reason, &r.org, &r.cert, &r.name); err != nil {
			rows.Close()
			return err
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range recs {
		details := map[string]any{"actionId": r.action, "reason": r.reason}
		if r.oldTarget != nil {
			details["oldTargetId"] = r.oldTarget
		}
		if r.name != nil {
			details["actionName"] = *r.name
		}
		if r.cert != nil {
			details["certificate"] = *r.cert
		}
		if err := aud.Record(ctx, audit.Event{Action: "action.step_removed", ResourceType: "grant", ResourceID: r.grant.String(),
			OrgID: r.org, Details: details, ActorType: "system"}); err != nil {
			return err
		}
		log.Warn("removed a grant step: its action named another target", "grant", r.grant, "action", r.action, "reason", r.reason)
		if _, err := pool.Exec(ctx, `DELETE FROM migrated_step_removals WHERE grant_id = $1 AND action_id = $2`, r.grant, r.action); err != nil {
			return err
		}
	}
	return nil
}
