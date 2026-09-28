// Package kek reports the server's key-encryption key status and runs the
// rewrap job that moves sealed columns from a previous KEK onto the active
// one (Phase 5A, ADR 0014).
package kek

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

// PageSize is how many rows RewrapWorker reads per keyset page, for every
// table in Tables.
const PageSize = 200

// ErrRunning means a rewrap job is already queued, running or scheduled for
// retry; startRewrap answers 409 for it instead of enqueueing a second one.
var ErrRunning = errors.New("kek: a rewrap is already running")

// Ref identifies one key-encryption key without its key material: the wire
// shape behind gen.KekRef, kept independent of internal/api/gen the way
// crypto.TransitKeyInfo mirrors vault.KeyInfo (see crypto.TransitAPI's doc
// comment) so this package never has to import the generated API types.
type Ref struct {
	Kind  string
	KEKID string
}

// Info is the active KEK's static identity, built once at boot
// (cmd/certforge/kek.go) from config.KEKConfig/config.VaultKEK: only the
// boot path knows the configured kind and Vault address. Service itself
// only ever deals with crypto.KeyWrapper values, which carry an opaque id
// and nothing else.
type Info struct {
	// Kind is config.KEKKindStatic or config.KEKKindVaultTransit.
	Kind  string
	KEKID string
	// VaultAddress is set only when Kind is config.KEKKindVaultTransit.
	VaultAddress string
	Previous     []Ref
}

// Inserter is the subset of *river.Client[pgx.Tx] Service needs to enqueue
// a rewrap job; production passes the real river client, tests a fake.
type Inserter interface {
	InsertTx(ctx context.Context, tx pgx.Tx, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

// Service reports the active KEK's status (getKeysStatus) and starts and
// runs its rewrap job (startRewrap, RewrapWorker).
type Service struct {
	Env      *crypto.Envelope
	Settings *settings.Store
	Pool     *pgxpool.Pool
	River    Inserter
	Audit    *audit.Auditor
	Info     Info

	// Log and Now default to slog.Default and time.Now; rewrap_test.go
	// overrides Now for deterministic StartedAt/FinishedAt values.
	Log *slog.Logger
	Now func() time.Time

	// store backs the rewrap scan and CAS writes: built lazily from Pool in
	// production (tableStore), or set directly by an in-package test
	// (rewrap_test.go) to a fake that never touches Postgres.
	store Store
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// tableStore returns the Store backing the rewrap scan, building a
// Postgres-backed one from Pool on first use.
func (s *Service) tableStore() Store {
	if s.store == nil {
		s.store = &sqlStore{q: sqlcgen.New(s.Pool)}
	}
	return s.store
}

// activeWrapper returns the envelope's active KeyWrapper.
func (s *Service) activeWrapper() crypto.KeyWrapper {
	for _, w := range s.Env.Wrappers() {
		if w.ID() == s.Env.KEKID() {
			return w
		}
	}
	// crypto.NewEnvelope always includes the active wrapper in Wrappers();
	// this is an invariant violation, not a runtime condition to recover
	// from cleanly.
	panic("kek: active KEK id not found among envelope wrappers")
}

// RegisterRiver adds RewrapWorker to workers. There is no periodic job: a
// rewrap only ever starts at boot (EnqueueIfNeeded) or via startRewrap.
func (s *Service) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &RewrapWorker{Service: s})
	return nil
}
