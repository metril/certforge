package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/audit"
)

// auditMigratedStepRemovals reports the grant steps migration 00040 dropped
// (an action that named another target): one audit event and one warning per
// row, then the row is gone. Each row is claimed by a DELETE ... SKIP LOCKED
// in a transaction that also writes its event, so concurrent replicas audit a
// row once; a row whose audit write fails stays for the next start.
func auditMigratedStepRemovals(ctx context.Context, pool *pgxpool.Pool, aud *audit.Auditor, log *slog.Logger) error {
	for {
		more, err := auditOneRemoval(ctx, pool, aud, log)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

func auditOneRemoval(ctx context.Context, pool *pgxpool.Pool, aud *audit.Auditor, log *slog.Logger) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var (
		grant, action uuid.UUID
		oldTarget     *uuid.UUID
		reason        string
	)
	err = tx.QueryRow(ctx, `DELETE FROM migrated_step_removals WHERE ctid = (
			SELECT ctid FROM migrated_step_removals ORDER BY created_at, grant_id
			FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING grant_id, action_id, old_target_id, reason`).Scan(&grant, &action, &oldTarget, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var (
		org        *uuid.UUID
		cert, name *string
	)
	if err := tx.QueryRow(ctx, `SELECT
			(SELECT c.org_id FROM client_cert_grants g JOIN certificates c ON c.id = g.cert_id WHERE g.id = $1),
			(SELECT c.name FROM client_cert_grants g JOIN certificates c ON c.id = g.cert_id WHERE g.id = $1),
			(SELECT name FROM actions WHERE id = $2)`, grant, action).Scan(&org, &cert, &name); err != nil {
		return false, err
	}
	details := map[string]any{"actionId": action, "reason": reason}
	if oldTarget != nil {
		details["oldTargetId"] = oldTarget
	}
	if name != nil {
		details["actionName"] = *name
	}
	if cert != nil {
		details["certificate"] = *cert
	}
	if err := aud.Record(ctx, audit.Event{Action: "action.step_removed", ResourceType: "grant", ResourceID: grant.String(),
		OrgID: org, Details: details, ActorType: "system"}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	log.Warn("removed a grant step: its action named another target", "grant", grant, "action", action, "reason", reason)
	return true, nil
}
