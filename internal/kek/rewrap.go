package kek

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

// RewrapArgs is the rewrap job. It carries no fields: RewrapWorker always
// walks every table (Tables) against the Service's current envelope.
type RewrapArgs struct{}

// Kind implements river.JobArgs.
func (RewrapArgs) Kind() string { return "certforge_kek_rewrap" }

// InsertOpts makes the job unique by kind alone while
// available/pending/running/retryable/scheduled: only one rewrap ever runs
// at a time. Completed is deliberately excluded (same as issuance.IssueArgs)
// so a later boot or startRewrap call can always enqueue a fresh one.
func (RewrapArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending,
				rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled},
		},
	}
}

// RewrapWorker runs one rewrap job: the canary row first (a fast, explicit
// check — TestRewrapCanaryFirstFailsFast), then every table in Tables
// order, paging PageSize rows at a time and persisting progress to
// settings.RewrapKey after every page.
type RewrapWorker struct {
	river.WorkerDefaults[RewrapArgs]
	Service *Service
}

// Timeout implements river.Worker: -1 disables river's 1-minute default,
// which would cancel a rewrap of a large database mid-run. Progress is
// persisted per page, so a rescued or retried run resumes where it stopped.
func (w *RewrapWorker) Timeout(*river.Job[RewrapArgs]) time.Duration { return -1 }

// Work implements river.Worker.
func (w *RewrapWorker) Work(ctx context.Context, _ *river.Job[RewrapArgs]) error {
	_, err := w.Service.run(ctx)
	return err
}

// RewrapTable is one table RewrapWorker walks, in Tables order.
type RewrapTable string

// The tables RewrapWorker walks, in visit order.
const (
	TableSettings               RewrapTable = "settings"
	TableCAs                    RewrapTable = "cas"
	TableAcmeAccounts           RewrapTable = "acme_accounts"
	TableDNSProviderCredentials RewrapTable = "dns_provider_credentials"
	TableOutputSpecs            RewrapTable = "output_specs"
	TableAgentCAs               RewrapTable = "agent_cas"
	TableCertificateVersions    RewrapTable = "certificate_versions"
	TableNotificationChannels   RewrapTable = "notification_channels"
	TableDeployTargets          RewrapTable = "deploy_targets"
)

// Tables is the fixed visit order. notification_channels and
// deploy_targets are each appended, not inserted, as their phases added
// them (Deviations R10, 7A's Global Constraints): deploy_targets is last.
var Tables = []RewrapTable{
	TableSettings, TableCAs, TableAcmeAccounts, TableDNSProviderCredentials,
	TableOutputSpecs, TableAgentCAs, TableCertificateVersions, TableNotificationChannels,
	TableDeployTargets,
}

// tableColumns lists each table's sealed columns, in the order a row's
// columns are visited. cas has two: both are visited in the same row pass,
// and their outcomes are tallied into cas's single TableStatus entry.
var tableColumns = map[RewrapTable][]string{
	TableSettings:               {"secret"},
	TableCAs:                    {"eab_hmac", "secret_cfg"},
	TableAcmeAccounts:           {"account_key"},
	TableDNSProviderCredentials: {"secret_cfg"},
	TableOutputSpecs:            {"password"},
	TableAgentCAs:               {"key"},
	TableCertificateVersions:    {"private_key"},
	TableNotificationChannels:   {"secret_cfg"},
	TableDeployTargets:          {"secret_cfg"},
}

// RewrapStatus is a rewrap run's progress, from startRewrap to completion;
// persisted at settings.RewrapKey after every page so getKeysStatus can
// report it while the job is still running. This is the shape behind
// gen.RewrapStatus, kept independent of internal/api/gen (Info's doc
// comment explains why); its json tags match that schema's property names
// directly (rather than going through api/keys.go's field-by-field mapping)
// since this struct is also what gets marshalled into the settings table.
type RewrapStatus struct {
	Running        bool          `json:"running"`
	StartedAt      time.Time     `json:"startedAt"`
	FinishedAt     *time.Time    `json:"finishedAt"`
	ActiveKEKID    string        `json:"activeKekId"`
	PreviousKEKIDs []string      `json:"previousKekIds"`
	Tables         []TableStatus `json:"tables"`
	// Remaining is the sum of every table's Remaining, refreshed by each
	// table's final summary pass (countRemaining).
	Remaining int64  `json:"remaining"`
	Error     string `json:"error"`
}

// TableStatus is rewrap progress for one table (gen.RewrapTableStatus).
// Scanned counts rows visited; Rewrapped and Remaining count sealed columns
// (cas visits one row per Scanned but tallies two independent columns into
// the same entry). Remaining starts as the page-scan's lost-race count and
// is then replaced by a final, read-only recount of blobs still on a
// non-active id, which also catches a row whose column changed after this
// table's keyset walk had already passed it by.
type TableStatus struct {
	Table     RewrapTable `json:"table"`
	Scanned   int64       `json:"scanned"`
	Rewrapped int64       `json:"rewrapped"`
	Remaining int64       `json:"remaining"`
}

// Row is one page row: PK identifies it (a uuid.UUID's String(), or the
// settings table's text key), Cols holds the sealed column values named in
// tableColumns (nil = SQL NULL, nothing to rewrap at that column).
type Row struct {
	PK   string
	Cols map[string][]byte
}

// Store is what RewrapWorker needs from the database: a single-row lookup
// for the canary, keyset paging and compare-and-swap updates for every
// sealed column. sqlStore backs it with Postgres in production;
// rewrap_test.go fakes it entirely in memory so the paging/counting/race
// logic is tested without one.
type Store interface {
	// Canary returns the settings row at settings.CanaryKey. ok is false
	// when it does not exist yet (nothing sealed to check).
	Canary(ctx context.Context) (row Row, ok bool, err error)
	// Page returns up to limit rows of table with PK > after, ordered by PK
	// ascending. after == "" starts from the beginning.
	Page(ctx context.Context, table RewrapTable, after string, limit int32) ([]Row, error)
	// CAS updates table's col at pk from oldVal to newVal, only if the
	// stored value still equals oldVal. It reports whether the update
	// applied; false means another writer changed it first (a lost race).
	CAS(ctx context.Context, table RewrapTable, pk, col string, oldVal, newVal []byte) (bool, error)
}

// run performs one full rewrap attempt: the canary first, then every table.
// A canary or table error stops the run immediately (fails fast) and is
// recorded on the returned status; the caller (Work) returns it so river
// retries under RewrapArgs.InsertOpts (MaxAttempts 3).
func (s *Service) run(ctx context.Context) (*RewrapStatus, error) {
	active := s.activeWrapper()
	// A Transit-backed active KEK caches its key's latest version
	// (crypto.TransitWrapper.Rewrap's doc comment) so a same-id rewrap
	// (a Vault key-version bump) doesn't call TransitKeyInfo once per
	// stored blob; reset it once here, at the start of the run, so a
	// version bump inside Vault since the last run is picked up.
	if r, ok := active.(interface{ ResetKeyInfoCache() }); ok {
		r.ResetKeyInfoCache()
	}
	status := &RewrapStatus{
		Running: true, StartedAt: s.now(), ActiveKEKID: active.ID(),
		PreviousKEKIDs: s.previousKEKIDs(), Tables: initialTableStatuses(),
	}
	if err := s.saveStatus(ctx, status); err != nil {
		return status, err
	}

	store := s.tableStore()
	if err := s.rewrapCanary(ctx, active); err != nil {
		return status, s.fail(ctx, store, active, status, err)
	}

	for i := range Tables {
		if err := s.rewrapTable(ctx, store, active, i, status); err != nil {
			return status, s.fail(ctx, store, active, status, err)
		}
	}

	status.Running = false
	fin := s.now()
	status.FinishedAt = &fin
	status.Remaining = sumRemaining(status.Tables)
	status.Error = ""
	if err := s.saveStatus(ctx, status); err != nil {
		return status, err
	}
	s.recordFinished(ctx, status)
	return status, nil
}

// fail marks status as finished with cause and best-effort saves it, then
// returns cause unchanged for the caller to propagate. A failed run must
// not report remaining=0 by default — the KEK-rotation runbook reads that
// as "safe to drop CF_KEK_PREVIOUS" — so before saving, fail runs the same
// read-only countRemaining pass a successful run finishes with, over every
// table, even ones this run never reached (a canary failure aborts before
// any table is scanned at all): a recount failure for one table is logged
// and that table's Remaining is left at whatever it already was, rather
// than failing the failure path itself.
func (s *Service) fail(ctx context.Context, store Store, active crypto.KeyWrapper, status *RewrapStatus, cause error) error {
	status.Running = false
	fin := s.now()
	status.FinishedAt = &fin
	status.Error = cause.Error()
	for i := range status.Tables {
		table := status.Tables[i].Table
		n, err := s.countRemaining(ctx, store, active, table, tableColumns[table])
		if err != nil {
			s.log().Error("kek rewrap: count remaining after failure", "table", table, "err", err)
			continue
		}
		status.Tables[i].Remaining = n
	}
	status.Remaining = sumRemaining(status.Tables)
	if err := s.saveStatus(ctx, status); err != nil {
		s.log().Error("kek rewrap: save status after failure", "err", err)
	}
	return cause
}

// rewrapCanary rewraps the settings.CanaryKey row first, ahead of the main
// table walk: a fast, cheap check that fails the whole run immediately
// (TestRewrapCanaryFirstFailsFast) if even this one row cannot be moved
// (for example a previous KEK misconfigured or removed too soon), instead
// of discovering that only after scanning far larger tables. A lost race on
// this single row is not itself a failure: the settings table's own pass
// (TableSettings, first in Tables) revisits it normally.
func (s *Service) rewrapCanary(ctx context.Context, active crypto.KeyWrapper) error {
	store := s.tableStore()
	row, ok, err := store.Canary(ctx)
	if err != nil {
		return fmt.Errorf("kek: rewrap canary: %w", err)
	}
	if !ok {
		return nil
	}
	raw := row.Cols["secret"]
	newRaw, write, err := s.rewrapBlob(ctx, active, raw)
	if err != nil {
		return fmt.Errorf("kek: rewrap canary: %w", err)
	}
	if !write {
		return nil
	}
	if _, err := store.CAS(ctx, TableSettings, row.PK, "secret", raw, newRaw); err != nil {
		return fmt.Errorf("kek: rewrap canary: cas: %w", err)
	}
	return nil
}

// rewrapTable walks table in keyset pages of PageSize, updating
// status.Tables[idx] in place and saving status after every page (After
// each page, crypto.rewrap is Set). It finishes with a read-only summary
// pass that recounts blobs still on a non-active id.
func (s *Service) rewrapTable(ctx context.Context, store Store, active crypto.KeyWrapper, idx int, status *RewrapStatus) error {
	table := status.Tables[idx].Table
	cols := tableColumns[table]
	after := ""
	for {
		rows, err := store.Page(ctx, table, after, PageSize)
		if err != nil {
			return fmt.Errorf("kek: rewrap %s: page: %w", table, err)
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			status.Tables[idx].Scanned++
			for _, col := range cols {
				raw := row.Cols[col]
				newRaw, write, err := s.rewrapBlob(ctx, active, raw)
				if err != nil {
					return fmt.Errorf("kek: rewrap %s %s.%s: %w", table, row.PK, col, err)
				}
				if !write {
					continue
				}
				ok, err := store.CAS(ctx, table, row.PK, col, raw, newRaw)
				if err != nil {
					return fmt.Errorf("kek: rewrap %s %s.%s: cas: %w", table, row.PK, col, err)
				}
				if ok {
					status.Tables[idx].Rewrapped++
				} else {
					status.Tables[idx].Remaining++
				}
			}
		}
		after = rows[len(rows)-1].PK
		// Refresh the overall sum from what's known so far after every
		// page, not only once at the very end (run's success path): a
		// mid-run status polled from GET /keys/status must not sit at a
		// stale 0 while a large table is still being walked.
		status.Remaining = sumRemaining(status.Tables)
		if err := s.saveStatus(ctx, status); err != nil {
			return err
		}
		if len(rows) < PageSize {
			break
		}
	}
	remaining, err := s.countRemaining(ctx, store, active, table, cols)
	if err != nil {
		return fmt.Errorf("kek: rewrap %s: summary: %w", table, err)
	}
	status.Tables[idx].Remaining = remaining
	status.Remaining = sumRemaining(status.Tables)
	return s.saveStatus(ctx, status)
}

// countRemaining is the final summary pass: a read-only walk of table
// counting blobs whose KEKID is not active's, without decrypting or writing
// anything.
func (s *Service) countRemaining(ctx context.Context, store Store, active crypto.KeyWrapper, table RewrapTable, cols []string) (int64, error) {
	var n int64
	after := ""
	for {
		rows, err := store.Page(ctx, table, after, PageSize)
		if err != nil {
			return 0, err
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			for _, col := range cols {
				if id, ok := blobKEKID(row.Cols[col]); ok && id != active.ID() {
					n++
				}
			}
		}
		after = rows[len(rows)-1].PK
		if len(rows) < PageSize {
			break
		}
	}
	return n, nil
}

// rewrapBlob decides what to do with one column's raw stored bytes:
//   - nil (SQL NULL): nothing to do.
//   - not a valid crypto.Blob: skipped (a value is skipped and counted;
//     the caller already counted this row as scanned).
//   - already sealed under active: rewrapped in place only if active
//     implements crypto.Rewrapper and reports it changed (a Vault Transit
//     key-version bump); otherwise skipped.
//   - sealed under a previous KEK: fully decrypted and re-encrypted through
//     s.Env (fresh DEK, nonce and ciphertext), not just a DEK-level rewrap:
//     the ciphertext's AEAD binds KEKID as additional data (Envelope.Encrypt),
//     so relabelling KEKID onto the same ciphertext would break
//     authentication on the next read. s.Env.Decrypt reports crypto.ErrWrongKEK
//     if no configured wrapper (active or previous) matches its KEKID.
//
// write is true only when newRaw must be written back via a CAS update.
func (s *Service) rewrapBlob(ctx context.Context, active crypto.KeyWrapper, raw []byte) (newRaw []byte, write bool, err error) {
	if raw == nil {
		return nil, false, nil
	}
	var b crypto.Blob
	if err := b.Unmarshal(raw); err != nil {
		return nil, false, nil
	}
	if b.KEKID == active.ID() {
		rw, ok := active.(crypto.Rewrapper)
		if !ok {
			return nil, false, nil
		}
		newWrapped, changed, err := rw.Rewrap(ctx, b.WrappedDEK)
		if err != nil {
			return nil, false, fmt.Errorf("rewrap under active KEK: %w", err)
		}
		if !changed {
			return nil, false, nil
		}
		nb := crypto.Blob{KEKID: b.KEKID, WrappedDEK: newWrapped, Nonce: b.Nonce, Ciphertext: b.Ciphertext}
		return nb.Marshal(), true, nil
	}
	pt, err := s.Env.Decrypt(ctx, b)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt under previous KEK %s: %w", b.KEKID, err)
	}
	defer clear(pt)
	nb, err := s.Env.Encrypt(ctx, pt)
	if err != nil {
		return nil, false, fmt.Errorf("re-encrypt under active KEK: %w", err)
	}
	return nb.Marshal(), true, nil
}

// blobKEKID reports raw's KEKID header without decrypting anything. ok is
// false for a nil value or one that does not parse as a crypto.Blob.
func blobKEKID(raw []byte) (id string, ok bool) {
	if raw == nil {
		return "", false
	}
	var b crypto.Blob
	if err := b.Unmarshal(raw); err != nil {
		return "", false
	}
	return b.KEKID, true
}

func initialTableStatuses() []TableStatus {
	ts := make([]TableStatus, len(Tables))
	for i, t := range Tables {
		ts[i] = TableStatus{Table: t}
	}
	return ts
}

func sumRemaining(tables []TableStatus) int64 {
	var n int64
	for _, t := range tables {
		n += t.Remaining
	}
	return n
}

func (s *Service) previousKEKIDs() []string {
	ids := make([]string, 0, len(s.Info.Previous))
	for _, r := range s.Info.Previous {
		ids = append(ids, r.KEKID)
	}
	return ids
}

// saveStatus persists status to settings.RewrapKey. s.Settings is nil only
// in unit tests exercising the rewrap algorithm without a database
// (rewrap_test.go); production always sets it.
func (s *Service) saveStatus(ctx context.Context, status *RewrapStatus) error {
	if s.Settings == nil {
		return nil
	}
	return s.Settings.Set(ctx, settings.RewrapKey, status)
}

// loadStatus reads the most recent rewrap's status, nil if one has never run.
func (s *Service) loadStatus(ctx context.Context) (*RewrapStatus, error) {
	if s.Settings == nil {
		return nil, nil
	}
	var status RewrapStatus
	err := s.Settings.Get(ctx, settings.RewrapKey, &status)
	if errors.Is(err, settings.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &status, nil
}

// recordFinished audits kek.rewrap_finished as the system actor. s.Audit is
// nil only in unit tests (same as saveStatus above); production always
// sets it.
func (s *Service) recordFinished(ctx context.Context, status *RewrapStatus) {
	if s.Audit == nil {
		return
	}
	var rewrapped int64
	for _, t := range status.Tables {
		rewrapped += t.Rewrapped
	}
	if err := s.Audit.Record(ctx, audit.Event{
		Action: "kek.rewrap_finished", ResourceType: "kek", ActorType: "system",
		Details: map[string]any{"rewrapped": rewrapped, "remaining": status.Remaining},
	}); err != nil {
		s.log().Error("kek rewrap: audit record failed", "err", err)
	}
}

// EnqueueIfNeeded enqueues a rewrap job at boot when there is anything to
// do: previous KEKs configured, or the active wrapper can itself move blobs
// onto newer key material (crypto.Rewrapper, a Transit key-version bump).
// It reports whether a job was actually inserted.
func (s *Service) EnqueueIfNeeded(ctx context.Context) (bool, error) {
	_, isRewrapper := s.activeWrapper().(crypto.Rewrapper)
	if len(s.Info.Previous) == 0 && !isRewrapper {
		return false, nil
	}
	return s.enqueue(ctx)
}

// StartRewrap enqueues a rewrap job (startRewrap), returning ErrRunning if
// one is already queued, running or scheduled for retry.
func (s *Service) StartRewrap(ctx context.Context) error {
	started, err := s.enqueue(ctx)
	if err != nil {
		return err
	}
	if !started {
		return ErrRunning
	}
	return nil
}

// enqueue inserts a RewrapArgs job inside its own transaction (InsertTx),
// reporting whether it was actually inserted: false means a job with this
// kind was already available/pending/running/retryable/scheduled
// (RewrapArgs.InsertOpts makes it unique on that alone), so this call was a
// harmless no-op rather than a stacked duplicate.
func (s *Service) enqueue(ctx context.Context) (bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	res, err := s.River.InsertTx(ctx, tx, RewrapArgs{}, nil)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

// sqlStore backs Store with Postgres.
type sqlStore struct{ q *sqlcgen.Queries }

func (s *sqlStore) Canary(ctx context.Context) (Row, bool, error) {
	row, err := s.q.RewrapSettingsGet(ctx, settings.CanaryKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return Row{}, false, nil
	}
	if err != nil {
		return Row{}, false, err
	}
	return Row{PK: row.Key, Cols: map[string][]byte{"secret": row.Secret}}, true, nil
}

func parseAfterUUID(after string) (*uuid.UUID, error) {
	if after == "" {
		return nil, nil
	}
	u, err := uuid.Parse(after)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

//nolint:gocyclo // one page query per table; a table-name switch, not conditional complexity
func (s *sqlStore) Page(ctx context.Context, table RewrapTable, after string, limit int32) ([]Row, error) {
	switch table {
	case TableSettings:
		var a *string
		if after != "" {
			a = &after
		}
		rows, err := s.q.RewrapSettingsPage(ctx, sqlcgen.RewrapSettingsPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.Key, Cols: map[string][]byte{"secret": r.Secret}}
		}
		return out, nil
	case TableCAs:
		a, err := parseAfterUUID(after)
		if err != nil {
			return nil, err
		}
		rows, err := s.q.RewrapCasPage(ctx, sqlcgen.RewrapCasPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.ID.String(), Cols: map[string][]byte{"eab_hmac": r.EabHmac, "secret_cfg": r.SecretCfg}}
		}
		return out, nil
	case TableAcmeAccounts:
		a, err := parseAfterUUID(after)
		if err != nil {
			return nil, err
		}
		rows, err := s.q.RewrapAcmeAccountsPage(ctx, sqlcgen.RewrapAcmeAccountsPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.ID.String(), Cols: map[string][]byte{"account_key": r.AccountKey}}
		}
		return out, nil
	case TableDNSProviderCredentials:
		a, err := parseAfterUUID(after)
		if err != nil {
			return nil, err
		}
		rows, err := s.q.RewrapDnsProviderCredentialsPage(ctx, sqlcgen.RewrapDnsProviderCredentialsPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.ID.String(), Cols: map[string][]byte{"secret_cfg": r.SecretCfg}}
		}
		return out, nil
	case TableOutputSpecs:
		a, err := parseAfterUUID(after)
		if err != nil {
			return nil, err
		}
		rows, err := s.q.RewrapOutputSpecsPage(ctx, sqlcgen.RewrapOutputSpecsPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.ID.String(), Cols: map[string][]byte{"password": r.Password}}
		}
		return out, nil
	case TableAgentCAs:
		a, err := parseAfterUUID(after)
		if err != nil {
			return nil, err
		}
		rows, err := s.q.RewrapAgentCasPage(ctx, sqlcgen.RewrapAgentCasPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.ID.String(), Cols: map[string][]byte{"key": r.Key}}
		}
		return out, nil
	case TableCertificateVersions:
		a, err := parseAfterUUID(after)
		if err != nil {
			return nil, err
		}
		rows, err := s.q.RewrapCertificateVersionsPage(ctx, sqlcgen.RewrapCertificateVersionsPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.ID.String(), Cols: map[string][]byte{"private_key": r.PrivateKey}}
		}
		return out, nil
	case TableNotificationChannels:
		a, err := parseAfterUUID(after)
		if err != nil {
			return nil, err
		}
		rows, err := s.q.RewrapNotificationChannelsPage(ctx, sqlcgen.RewrapNotificationChannelsPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.ID.String(), Cols: map[string][]byte{"secret_cfg": r.SecretCfg}}
		}
		return out, nil
	case TableDeployTargets:
		a, err := parseAfterUUID(after)
		if err != nil {
			return nil, err
		}
		rows, err := s.q.RewrapDeployTargetsPage(ctx, sqlcgen.RewrapDeployTargetsPageParams{Limit: limit, After: a})
		if err != nil {
			return nil, err
		}
		out := make([]Row, len(rows))
		for i, r := range rows {
			out[i] = Row{PK: r.ID.String(), Cols: map[string][]byte{"secret_cfg": r.SecretCfg}}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("kek: unknown rewrap table %q", table)
	}
}

//nolint:gocyclo // one CAS query per (table, column) pair, not conditional complexity
func (s *sqlStore) CAS(ctx context.Context, table RewrapTable, pk, col string, oldVal, newVal []byte) (bool, error) {
	switch {
	case table == TableSettings && col == "secret":
		n, err := s.q.RewrapSettingsSecretCAS(ctx, sqlcgen.RewrapSettingsSecretCASParams{Key: pk, Secret: newVal, Secret_2: oldVal})
		return n > 0, err
	case table == TableCAs && col == "eab_hmac":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapCasEabHmacCAS(ctx, sqlcgen.RewrapCasEabHmacCASParams{ID: id, EabHmac: newVal, EabHmac_2: oldVal})
		return n > 0, err
	case table == TableCAs && col == "secret_cfg":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapCasSecretCfgCAS(ctx, sqlcgen.RewrapCasSecretCfgCASParams{ID: id, SecretCfg: newVal, SecretCfg_2: oldVal})
		return n > 0, err
	case table == TableAcmeAccounts && col == "account_key":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapAcmeAccountsKeyCAS(ctx, sqlcgen.RewrapAcmeAccountsKeyCASParams{ID: id, AccountKey: newVal, AccountKey_2: oldVal})
		return n > 0, err
	case table == TableDNSProviderCredentials && col == "secret_cfg":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapDnsProviderCredentialsSecretCAS(ctx, sqlcgen.RewrapDnsProviderCredentialsSecretCASParams{ID: id, SecretCfg: newVal, SecretCfg_2: oldVal})
		return n > 0, err
	case table == TableOutputSpecs && col == "password":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapOutputSpecsPasswordCAS(ctx, sqlcgen.RewrapOutputSpecsPasswordCASParams{ID: id, Password: newVal, Password_2: oldVal})
		return n > 0, err
	case table == TableAgentCAs && col == "key":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapAgentCasKeyCAS(ctx, sqlcgen.RewrapAgentCasKeyCASParams{ID: id, Key: newVal, Key_2: oldVal})
		return n > 0, err
	case table == TableCertificateVersions && col == "private_key":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapCertificateVersionsKeyCAS(ctx, sqlcgen.RewrapCertificateVersionsKeyCASParams{ID: id, PrivateKey: newVal, PrivateKey_2: oldVal})
		return n > 0, err
	case table == TableNotificationChannels && col == "secret_cfg":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapNotificationChannelsSecretCAS(ctx, sqlcgen.RewrapNotificationChannelsSecretCASParams{ID: id, SecretCfg: newVal, SecretCfg_2: oldVal})
		return n > 0, err
	case table == TableDeployTargets && col == "secret_cfg":
		id, err := uuid.Parse(pk)
		if err != nil {
			return false, err
		}
		n, err := s.q.RewrapDeployTargetsSecretCAS(ctx, sqlcgen.RewrapDeployTargetsSecretCASParams{ID: id, SecretCfg: newVal, SecretCfg_2: oldVal})
		return n > 0, err
	default:
		return false, fmt.Errorf("kek: unknown rewrap column %s.%s", table, col)
	}
}
