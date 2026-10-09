//go:build integration

package notify_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify"
)

// fakeNotifier is a stand-in Notifier (Task 3 has no real notifier types
// yet; those are Task 4/5). err, when set, is returned by every Send.
type fakeNotifier struct {
	typ string
	err error

	mu    sync.Mutex
	calls []notify.Event
}

func (f *fakeNotifier) Type() string   { return f.typ }
func (f *fakeNotifier) Name() string   { return "Fake" }
func (f *fakeNotifier) Schema() []byte { return []byte(`{}`) }

func (f *fakeNotifier) Send(_ context.Context, ev notify.Event, _ notify.Target, _ map[string]any, _ map[string]string) error {
	f.mu.Lock()
	f.calls = append(f.calls, ev)
	f.mu.Unlock()
	return f.err
}

func (f *fakeNotifier) sendCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// deliverJob builds a *river.Job[DeliverArgs] as river would hand it to
// Work: attempt is the JobRow's own Attempt (1 on the first try, per
// rivertype.JobRow's own doc comment).
func deliverJob(args notify.DeliverArgs, attempt, maxAttempts int) *river.Job[notify.DeliverArgs] {
	return &river.Job[notify.DeliverArgs]{
		JobRow: &rivertype.JobRow{Attempt: attempt, MaxAttempts: maxAttempts},
		Args:   args,
	}
}

// deliveryRow reads back one notification_deliveries row's attempts,
// status and last_error.
func deliveryRow(t *testing.T, pool *pgxpool.Pool, args notify.DeliverArgs) (attempts int32, status, lastError string) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		"SELECT attempts, status, last_error FROM notification_deliveries WHERE event_id = $1 AND channel_id = $2",
		args.EventID, args.ChannelID,
	).Scan(&attempts, &status, &lastError)
	if err != nil {
		t.Fatalf("query delivery row: %v", err)
	}
	return attempts, status, lastError
}

func TestDeliverRecordsAttemptsAndFinalFailure(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)

	secret := "sekrit-value"
	sealed, err := cryptotest.PrefixBox{}.Seal(ctx, []byte(`{"token":"`+secret+`"}`))
	if err != nil {
		t.Fatalf("seal secret: %v", err)
	}
	insertChannel(t, pool, testChannel{orgID: org, typ: "webhook", secretCfg: sealed})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}
	ev := newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())
	if _, err := e.Emit(ctx, nil, ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	args := ins.first(t)

	notifier := &fakeNotifier{typ: "webhook", err: errors.New("upstream rejected token " + secret)}
	reg := notify.NewRegistry()
	reg.Register(notifier)
	w := &notify.DeliverWorker{Q: sqlcgen.New(pool), Box: cryptotest.PrefixBox{}, Registry: reg, BaseURL: "https://cf.example", Version: "1.0.0"}

	// First attempt: still short of MaxAttempts, so the delivery stays
	// pending for river to retry.
	workErr := w.Work(ctx, deliverJob(args, 1, 5))
	if workErr == nil {
		t.Fatal("Work returned nil for a failing Send")
	}
	// The error Work returns is what river stores in job.errors and logs
	// (batch-1 review finding 1) — it must be the already-redacted text,
	// never the raw sendErr, or the secret reaches river's own storage and
	// log even though notification_deliveries.last_error was scrubbed.
	if strings.Contains(workErr.Error(), secret) {
		t.Errorf("error returned to river leaked the secret: %q", workErr.Error())
	}
	attempts, status, lastError := deliveryRow(t, pool, args)
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
	if status != "pending" {
		t.Errorf("status = %q, want pending (not yet at MaxAttempts)", status)
	}
	if strings.Contains(lastError, secret) {
		t.Errorf("last_error leaked the secret: %q", lastError)
	}
	if !strings.Contains(lastError, "[redacted]") {
		t.Errorf("last_error was not redacted: %q", lastError)
	}

	// Final attempt (job.Attempt has reached MaxAttempts): status flips to
	// failed instead of staying pending.
	if err := w.Work(ctx, deliverJob(args, 5, 5)); err == nil {
		t.Fatal("Work returned nil for a failing Send on the final attempt")
	}
	attempts, status, lastError = deliveryRow(t, pool, args)
	if attempts != 5 {
		t.Errorf("attempts = %d, want 5", attempts)
	}
	if status != "failed" {
		t.Errorf("status = %q, want failed (at MaxAttempts)", status)
	}
	if strings.Contains(lastError, secret) {
		t.Errorf("last_error leaked the secret on final failure: %q", lastError)
	}

	if got := notifier.sendCount(); got != 2 {
		t.Errorf("notifier.Send called %d times, want 2", got)
	}
}

func TestDeliverSuccessMarksDelivered(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, typ: "webhook"})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}
	ev := newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())
	if _, err := e.Emit(ctx, nil, ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	args := ins.first(t)

	notifier := &fakeNotifier{typ: "webhook"}
	reg := notify.NewRegistry()
	reg.Register(notifier)
	w := &notify.DeliverWorker{Q: sqlcgen.New(pool), Box: cryptotest.PrefixBox{}, Registry: reg}

	if err := w.Work(ctx, deliverJob(args, 1, 5)); err != nil {
		t.Fatalf("Work: %v", err)
	}
	_, status, _ := deliveryRow(t, pool, args)
	if status != "delivered" {
		t.Errorf("status = %q, want delivered", status)
	}
	var deliveredAt *string
	if err := pool.QueryRow(ctx, "SELECT delivered_at::text FROM notification_deliveries WHERE event_id=$1 AND channel_id=$2",
		args.EventID, args.ChannelID).Scan(&deliveredAt); err != nil {
		t.Fatalf("query delivered_at: %v", err)
	}
	if deliveredAt == nil {
		t.Error("delivered_at is null after a successful delivery")
	}
}

func TestDeliverDisabledChannelFailsWithoutSend(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	chID := insertChannel(t, pool, testChannel{orgID: org, typ: "webhook"})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}
	ev := newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())
	if _, err := e.Emit(ctx, nil, ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	args := ins.first(t)

	// The channel is disabled after the job was already enqueued (a race
	// with the settled delivery), not before Emit matched it.
	if _, err := pool.Exec(ctx, "UPDATE notification_channels SET enabled = false WHERE id = $1", chID); err != nil {
		t.Fatalf("disable channel: %v", err)
	}

	notifier := &fakeNotifier{typ: "webhook"}
	reg := notify.NewRegistry()
	reg.Register(notifier)
	w := &notify.DeliverWorker{Q: sqlcgen.New(pool), Box: cryptotest.PrefixBox{}, Registry: reg}

	if err := w.Work(ctx, deliverJob(args, 1, 5)); err != nil {
		t.Fatalf("Work returned an error for a disabled channel: %v", err)
	}
	_, status, lastError := deliveryRow(t, pool, args)
	if status != "failed" {
		t.Errorf("status = %q, want failed", status)
	}
	if lastError != "channel disabled" {
		t.Errorf("last_error = %q, want %q", lastError, "channel disabled")
	}
	if got := notifier.sendCount(); got != 0 {
		t.Errorf("notifier.Send called %d times, want 0 (disabled channel)", got)
	}
}

func TestDeliverChannelDeleted(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	chID := insertChannel(t, pool, testChannel{orgID: org, typ: "webhook"})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}
	ev := newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())
	if _, err := e.Emit(ctx, nil, ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	args := ins.first(t)

	// Deleting the channel cascades away its pending delivery row too
	// (notification_deliveries.channel_id ON DELETE CASCADE).
	if _, err := pool.Exec(ctx, "DELETE FROM notification_channels WHERE id = $1", chID); err != nil {
		t.Fatalf("delete channel: %v", err)
	}

	notifier := &fakeNotifier{typ: "webhook"}
	reg := notify.NewRegistry()
	reg.Register(notifier)
	w := &notify.DeliverWorker{Q: sqlcgen.New(pool), Box: cryptotest.PrefixBox{}, Registry: reg}

	if err := w.Work(ctx, deliverJob(args, 1, 5)); err != nil {
		t.Fatalf("Work returned an error for a deleted channel: %v", err)
	}
	if got := notifier.sendCount(); got != 0 {
		t.Errorf("notifier.Send called %d times, want 0 (channel deleted)", got)
	}
}

// TestDeliverSkipsAlreadyDelivered: a re-run job for a delivery already
// marked delivered must not send again.
func TestDeliverSkipsAlreadyDelivered(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, typ: "webhook"})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}
	if _, err := e.Emit(ctx, nil, newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	args := ins.first(t)
	notifier := &fakeNotifier{typ: "webhook"}
	reg := notify.NewRegistry()
	reg.Register(notifier)
	w := &notify.DeliverWorker{Q: sqlcgen.New(pool), Box: cryptotest.PrefixBox{}, Registry: reg}

	for i := 0; i < 2; i++ {
		if err := w.Work(ctx, deliverJob(args, 1+i, 5)); err != nil {
			t.Fatalf("Work %d: %v", i, err)
		}
	}
	if got := notifier.sendCount(); got != 1 {
		t.Errorf("sends = %d, want 1", got)
	}
}

// flakyMarkDB fails the first n "mark delivered" writes.
type flakyMarkDB struct {
	sqlcgen.DBTX
	mu sync.Mutex
	n  int
}

func (f *flakyMarkDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "status = 'delivered'") {
		f.mu.Lock()
		fail := f.n > 0
		if fail {
			f.n--
		}
		f.mu.Unlock()
		if fail {
			return pgconn.CommandTag{}, errors.New("simulated write failure")
		}
	}
	return f.DBTX.Exec(ctx, sql, args...)
}

// TestDeliverRetriesMarkDeliveredNotSend: a failing "mark delivered" write is
// retried; the notifier is called once and the row ends delivered.
func TestDeliverRetriesMarkDeliveredNotSend(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, typ: "webhook"})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}
	if _, err := e.Emit(ctx, nil, newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	args := ins.first(t)
	notifier := &fakeNotifier{typ: "webhook"}
	reg := notify.NewRegistry()
	reg.Register(notifier)
	w := &notify.DeliverWorker{Q: sqlcgen.New(&flakyMarkDB{DBTX: pool, n: 2}), Box: cryptotest.PrefixBox{}, Registry: reg}

	if err := w.Work(ctx, deliverJob(args, 1, 5)); err != nil {
		t.Fatalf("Work: %v", err)
	}
	if got := notifier.sendCount(); got != 1 {
		t.Errorf("sends = %d, want 1", got)
	}
	if _, status, _ := deliveryRow(t, pool, args); status != "delivered" {
		t.Errorf("status = %q, want delivered", status)
	}
}

// A delivery whose send never runs (channel secrets cannot be opened) must
// still be recorded: failed once the job's last attempt has run.
func TestDeliverPreSendFailureIsRecorded(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, typ: "webhook", secretCfg: []byte("not-sealed")})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}
	if _, err := e.Emit(ctx, nil, newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	args := ins.first(t)

	notifier := &fakeNotifier{typ: "webhook"}
	reg := notify.NewRegistry()
	reg.Register(notifier)
	w := &notify.DeliverWorker{Q: sqlcgen.New(pool), Box: cryptotest.PrefixBox{}, Registry: reg}

	if err := w.Work(ctx, deliverJob(args, 1, 2)); err == nil {
		t.Fatal("Work = nil, want an error so river retries")
	}
	if _, status, _ := deliveryRow(t, pool, args); status != "pending" {
		t.Errorf("status after a non-final attempt = %q, want pending", status)
	}
	if err := w.Work(ctx, deliverJob(args, 2, 2)); err == nil {
		t.Fatal("Work = nil on the final attempt, want an error")
	}
	attempts, status, lastError := deliveryRow(t, pool, args)
	if status != "failed" || attempts != 2 || lastError == "" {
		t.Errorf("after final attempt: attempts=%d status=%q last_error=%q, want 2/failed/non-empty", attempts, status, lastError)
	}
	if got := notifier.sendCount(); got != 0 {
		t.Errorf("Send called %d times, want 0", got)
	}
}
