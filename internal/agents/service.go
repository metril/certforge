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
	Auditor  *audit.Auditor
	Settings *SettingsSource
	Hub      Hub
	Listener Reloader
	Log      *slog.Logger
	Now      func() time.Time

	seenMu sync.Mutex              //nolint:unused // used by a later task's heartbeat handler.
	seen   map[uuid.UUID]time.Time //nolint:unused // last_seen write coalescing, used by a later task's heartbeat handler.
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

func (s *Service) audit(ctx context.Context, e audit.Event) {
	if s.Auditor == nil {
		return
	}
	if err := s.Auditor.Record(ctx, e); err != nil {
		s.log().Error("audit record failed", "action", e.Action, "err", err)
	}
}
