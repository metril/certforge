package deploy

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// maxRemediations is how many times in a row auto-remediation may redeploy
// for the same observed fingerprint before it gives up (flap guard).
const maxRemediations = 3

// remediationAttempts is the configured cap, maxRemediations when unset.
func (d *Dispatcher) remediationAttempts(ctx context.Context) int {
	if d.RemediationAttempts != nil {
		if n := d.RemediationAttempts(ctx); n > 0 {
			return n
		}
	}
	return maxRemediations
}

func short(fp string) string {
	if len(fp) > 8 {
		return fp[:8]
	}
	return fp
}

// OnCheck implements monitor.DriftHandler: a grant-owned monitor's check
// marks a deployed server grant drifted when the endpoint serves a different
// certificate, optionally redeploys it, and clears the drift once the
// expected certificate is served again. It runs in the check's transaction.
func (d *Dispatcher) OnCheck(ctx context.Context, tx pgx.Tx, monitorID uuid.UUID, newState, observedFP, expectedFP string) (func(), error) {
	q := d.Q.WithTx(tx)
	var grantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT grant_id FROM external_monitors WHERE id = $1`, monitorID).Scan(&grantID); err != nil || grantID == nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		}
		return nil, err
	}
	row, err := q.ServerGrantForMonitor(ctx, *grantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	switch newState {
	case "ok":
		return nil, q.ResetServerDrift(ctx, sqlcgen.ResetServerDriftParams{CurrentVersionID: row.CurrentVersionID, GrantID: row.GrantID})
	case "mismatch":
		if row.Status != "deployed" && row.Status != "drift" {
			return nil, nil
		}
		// A renewal commits its new version before the deploy is enqueued, so
		// the monitor may briefly compare the old leaf with the new expected
		// fingerprint; that is a pending install, not drift.
		if row.CurrentVersionID == nil || row.VersionID == nil || *row.VersionID != *row.CurrentVersionID {
			return nil, nil
		}
		// One audit per drift episode: the first mismatch, or a mismatch on a
		// fingerprint no remediation has been tried on yet.
		same := row.RemediatedFp != nil && *row.RemediatedFp == observedFP
		firstSeen := row.Status == "deployed" && !same
		msg := fmt.Sprintf("monitor saw %s instead of %s", short(observedFP), short(expectedFP))
		if err := q.MarkServerDeploymentDrift(ctx, sqlcgen.MarkServerDeploymentDriftParams{LastError: msg, GrantID: row.GrantID}); err != nil {
			return nil, err
		}
		if row.AutoRemediate {
			maxAttempts := d.remediationAttempts(ctx)
			if same && row.Remediations >= int32(maxAttempts) {
				if err := q.MarkServerDeploymentDrift(ctx, sqlcgen.MarkServerDeploymentDriftParams{
					LastError: fmt.Sprintf("auto-remediation did not take effect after %d attempts", maxAttempts), GrantID: row.GrantID}); err != nil {
					return nil, err
				}
			} else {
				n := int32(1)
				if same {
					n = row.Remediations + 1
				}
				if err := q.RecordServerRemediation(ctx, sqlcgen.RecordServerRemediationParams{Remediations: n, RemediatedFp: &observedFP, GrantID: row.GrantID}); err != nil {
					return nil, err
				}
				if err := d.EnqueueTx(ctx, tx, q, row.GrantID, row.CurrentVersionID); err != nil {
					return nil, err
				}
			}
		}
		if !firstSeen || d.Auditor == nil {
			return nil, nil
		}
		ev := audit.Event{
			Action: "deployment.drift", ResourceType: "grant", ResourceID: row.GrantID.String(), OrgID: &row.OrgID, ActorType: "system",
			Details: map[string]any{
				"certificateId": row.CertID.String(), "versionId": uuidStr(row.VersionID), "monitorId": monitorID.String(),
				"observedFingerprint": observedFP, "expectedFingerprint": expectedFP,
			},
		}
		return func() {
			if err := d.Auditor.Record(context.WithoutCancel(ctx), ev); err != nil {
				d.log().Error("audit record failed", "action", ev.Action, "err", err)
			}
		}, nil
	}
	return nil, nil
}

func uuidStr(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
