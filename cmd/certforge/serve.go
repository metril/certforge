package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
)

func runServe(ctx context.Context, _ []string, _ io.Writer) error {
	cfg, log, pool, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	q := sqlcgen.New(pool)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(cfg.KEK.Key), cfg.KEK.Key))
	store := settings.NewStore(q, env)
	if err := store.EnsureCanary(ctx); err != nil {
		log.Error("KEK canary check failed; /readyz reports unavailable until the correct KEK is configured",
			"kek_id", env.KEKID(), "kek_source", cfg.KEK.Source, "err", err)
	}
	sections := settings.DefaultRegistry()
	metaReg := meta.NewRegistry()
	challenge.AddToMeta(metaReg)
	// Later phases register settings sections and other pluggable type schemas here.
	aud := audit.New(pool)
	sessions := authn.NewSessions(q, authn.DefaultSessionTTL)
	handler := api.NewRouter(api.Deps{
		Config: cfg, Log: log, Pool: pool, Queries: q, Settings: store, Sections: sections,
		Meta: metaReg, Sessions: sessions, Auditor: aud, Setup: setup.New(pool, aud, sections),
	})
	srv := &http.Server{
		Addr:              cfg.ListenHTTP,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go purgeSessions(ctx, sessions, log)
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenHTTP, "version", version)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	log.Info("shutting down")
	return srv.Shutdown(shutdownCtx)
}

func purgeSessions(ctx context.Context, s *authn.Sessions, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := s.PurgeExpired(ctx)
			if err != nil {
				log.Warn("session purge failed", "err", err)
			} else if n > 0 {
				log.Info("purged expired sessions", "count", n)
			}
		}
	}
}
