package agents

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// Hub is the WebSocket registry the service nudges (internal/agenthub).
type Hub interface {
	Send(clientID uuid.UUID, m agentproto.Message) bool
	Close(clientID uuid.UUID, code int, reason string)
	Connected(clientID uuid.UUID) bool
	Broadcast(m agentproto.Message) int
}

// Reloader re-reads the trust bundle and listener certificate (agentca.Listener).
type Reloader interface {
	Reload(ctx context.Context) error
}

// Service is the agents domain service. Hub and Listener may be nil.
type Service struct {
	Pool     *pgxpool.Pool
	Q        *sqlcgen.Queries
	CA       *agentca.Store
	Certs    *certstore.Store
	Box      crypto.Box // opens a layout's sealed export password
	Auditor  *audit.Auditor
	Settings *SettingsSource
	Hub      Hub
	Listener Reloader
	Log      *slog.Logger
	Now      func() time.Time

	// ChallengeReadyTimeout bounds how long Provider's Present waits for the
	// agent's challenge_ready reply after sending challenge_present; zero
	// means DefaultChallengeReadyTimeout. A field, not a const, so tests can
	// shorten it (see challenge.go).
	ChallengeReadyTimeout time.Duration

	seenMu     sync.Mutex
	seen       map[uuid.UUID]time.Time // last_seen write coalescing; touch writes at most once per touchEvery.
	seenPruned time.Time               // last time markSeen dropped idle entries.

	waiters challengeWaiters // keyed by (clientID, token); see challenge.go
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// CurrentSettings returns the resolved agents settings, or defaults when
// they cannot be read.
func (s *Service) CurrentSettings(ctx context.Context) Settings {
	if s.Settings == nil {
		return Resolve(Settings{}, "")
	}
	st, err := s.Settings.Get(ctx)
	if err != nil {
		s.log().Warn("agents settings unavailable; using defaults", "err", err)
		return Resolve(Settings{}, s.Settings.BaseURL())
	}
	return st
}

// Connected reports whether the client's agent holds a socket now.
func (s *Service) Connected(id uuid.UUID) bool { return s.Hub != nil && s.Hub.Connected(id) }

// OnlineCutoff is the oldest last_seen that still counts as online
// (now minus offlineAfterSeconds), so pull-only agents show online.
func (s *Service) OnlineCutoff(ctx context.Context) time.Time {
	return s.now().Add(-time.Duration(s.CurrentSettings(ctx).OfflineAfterSeconds) * time.Second)
}

// openPassword opens a layout's sealed export password; a nil/empty sealed
// value (no password stored) returns "" without touching s.Box.
func (s *Service) openPassword(ctx context.Context, sealed []byte) (string, error) {
	if len(sealed) == 0 {
		return "", nil
	}
	b, err := s.Box.Open(ctx, sealed)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *Service) audit(ctx context.Context, e audit.Event) {
	if s.Auditor == nil {
		return
	}
	if err := s.Auditor.Record(ctx, e); err != nil {
		s.log().Error("audit record failed", "action", e.Action, "err", err)
	}
}
