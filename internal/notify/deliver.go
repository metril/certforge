package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify/httpx"
)

// maxLastError bounds notification_deliveries.last_error (Shared contract:
// DeliveryResult.error/Channel.lastDelivery.error, <= 1000 chars).
const maxLastError = 1000

// deliverTimeout bounds one Notifier.Send call (task-3 brief).
const deliverTimeout = 45 * time.Second

// DeliverArgs is the river job delivering one event to one channel.
type DeliverArgs struct {
	EventID   uuid.UUID `json:"event_id"`
	ChannelID uuid.UUID `json:"channel_id"`
}

// Kind implements river.JobArgs.
func (DeliverArgs) Kind() string { return "certforge_notify_deliver" }

// InsertOpts makes the job unique per (event, channel) while queued,
// running or scheduled for retry (same shape as deploy.DeployArgs).
func (DeliverArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending,
				rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled},
		},
	}
}

// DeliverWorker runs DeliverArgs: loads the delivery, event and channel,
// opens the channel's secrets and calls the matching Notifier.
type DeliverWorker struct {
	river.WorkerDefaults[DeliverArgs]
	Q        *sqlcgen.Queries
	Box      crypto.Box
	Registry *Registry
	// BaseURL and Version fill Target for every Notifier.Send call
	// (CertForge's own public URL and build version).
	BaseURL string
	Version string
	Log     *slog.Logger
}

func (w *DeliverWorker) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

// Work implements river.Worker. A missing delivery, event or channel row
// (the channel or its event was deleted after this job was enqueued —
// notification_deliveries cascades on either FK) is simply done: nil, no
// retry. A disabled channel records a terminal "channel disabled" failure
// and is also done. Any other Send failure records the attempt and either
// leaves the delivery pending (river will retry) or marks it failed once
// this was the job's last attempt, and returns the (redacted, for river's
// own log) error so river schedules the retry — or gives up, having
// already recorded the terminal failure itself.
func (w *DeliverWorker) Work(ctx context.Context, job *river.Job[DeliverArgs]) error {
	if _, err := w.Q.GetNotificationDelivery(ctx, sqlcgen.GetNotificationDeliveryParams{
		EventID: job.Args.EventID, ChannelID: job.Args.ChannelID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}

	eventRow, err := w.Q.GetNotificationEvent(ctx, job.Args.EventID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}

	channel, err := w.Q.GetNotificationChannel(ctx, job.Args.ChannelID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}

	if !channel.Enabled {
		return w.terminalFail(ctx, job, "channel disabled")
	}

	notifier, ok := w.Registry.Get(channel.Type)
	if !ok {
		return w.terminalFail(ctx, job, fmt.Sprintf("unknown channel type %q", channel.Type))
	}

	secrets := map[string]string{}
	if len(channel.SecretCfg) > 0 {
		pt, err := w.Box.Open(ctx, channel.SecretCfg)
		if err != nil {
			return fmt.Errorf("notify: open channel secrets: %w", err)
		}
		if err := json.Unmarshal(pt, &secrets); err != nil {
			return fmt.Errorf("notify: decode channel secrets: %w", err)
		}
	}

	var cfg map[string]any
	if len(channel.Config) > 0 {
		if err := json.Unmarshal(channel.Config, &cfg); err != nil {
			return fmt.Errorf("notify: decode channel config: %w", err)
		}
	}

	target, err := w.target(ctx, eventRow.OrgID)
	if err != nil {
		return fmt.Errorf("notify: resolve org for delivery: %w", err)
	}

	sendCtx, cancel := context.WithTimeout(ctx, deliverTimeout)
	defer cancel()

	sendErr := notifier.Send(sendCtx, toEvent(eventRow), target, cfg, secrets)
	if sendErr != nil {
		return w.recordFailure(ctx, job, sendErr, secrets)
	}
	if err := w.Q.MarkNotificationDeliveryDelivered(ctx, sqlcgen.MarkNotificationDeliveryDeliveredParams{
		EventID: job.Args.EventID, ChannelID: job.Args.ChannelID, Attempts: int32(job.Attempt),
	}); err != nil {
		w.log().Error("notify: delivery success not recorded", "event", job.Args.EventID, "channel", job.Args.ChannelID, "err", err)
	}
	return nil
}

// target builds a Notifier's Target: OrgName is empty for a global event
// (orgID nil), else the org's current display name.
func (w *DeliverWorker) target(ctx context.Context, orgID *uuid.UUID) (Target, error) {
	t := Target{BaseURL: w.BaseURL, Version: w.Version}
	if orgID == nil {
		return t, nil
	}
	org, err := w.Q.GetOrg(ctx, *orgID)
	if err != nil {
		return Target{}, err
	}
	t.OrgName = org.Name
	return t, nil
}

// recordFailure redacts every secret value from sendErr, records the
// attempt (task-3 brief: attempts = job.Attempt, status failed once
// job.Attempt has reached the job's MaxAttempts, else still pending) and
// returns sendErr so river schedules the next retry or gives up.
func (w *DeliverWorker) recordFailure(ctx context.Context, job *river.Job[DeliverArgs], sendErr error, secrets map[string]string) error {
	status := "pending"
	if job.Attempt >= job.MaxAttempts {
		status = "failed"
	}
	msg := truncateUTF8(httpx.Redact(sendErr.Error(), secretValues(secrets)...), maxLastError)
	if err := w.Q.MarkNotificationDeliveryFailed(ctx, sqlcgen.MarkNotificationDeliveryFailedParams{
		EventID: job.Args.EventID, ChannelID: job.Args.ChannelID,
		Attempts: int32(job.Attempt), Status: status, LastError: msg,
	}); err != nil {
		w.log().Error("notify: delivery failure not recorded", "event", job.Args.EventID, "channel", job.Args.ChannelID, "err", err)
	}
	return sendErr
}

// terminalFail records a failed delivery with no Send attempt (a disabled
// channel or an unregistered type) and returns nil: there is nothing a
// river retry could fix, so the job is done, not retried.
func (w *DeliverWorker) terminalFail(ctx context.Context, job *river.Job[DeliverArgs], reason string) error {
	if err := w.Q.MarkNotificationDeliveryFailed(ctx, sqlcgen.MarkNotificationDeliveryFailedParams{
		EventID: job.Args.EventID, ChannelID: job.Args.ChannelID,
		Attempts: int32(job.Attempt), Status: "failed", LastError: reason,
	}); err != nil {
		w.log().Error("notify: delivery failure not recorded", "event", job.Args.EventID, "channel", job.Args.ChannelID, "err", err)
	}
	return nil
}

// toEvent converts a stored notification_events row back into an Event for
// Notifier.Send/Payload. Details decodes best-effort: Emit always writes
// valid JSON (a map or {}), so a decode error here would mean the row was
// written by something else entirely; details is simply left nil rather
// than failing the whole delivery over it.
func toEvent(row sqlcgen.NotificationEvent) Event {
	var details map[string]any
	_ = json.Unmarshal(row.Details, &details)
	return Event{
		ID:        row.ID,
		Kind:      row.Kind,
		At:        row.At,
		OrgID:     row.OrgID,
		Severity:  row.Severity,
		Resource:  Resource{Type: row.ResourceType, ID: row.ResourceID, Name: row.ResourceName},
		Summary:   row.Summary,
		Details:   details,
		DedupeKey: row.DedupeKey,
	}
}

// secretValues returns m's values, for passing to httpx.Redact.
func secretValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
