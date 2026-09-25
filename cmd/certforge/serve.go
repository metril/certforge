package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
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
	if err := issuance.RegisterSettings(sections); err != nil {
		return err
	}
	if err := authn.RegisterSettings(sections); err != nil {
		return err
	}
	authSettings, err := authn.NewSettingsSource(store, sections)
	if err != nil {
		return err
	}
	metaReg := meta.NewRegistry()
	challenge.AddToMeta(metaReg)
	// Later phases register settings sections and other pluggable type schemas here.
	box := crypto.EnvelopeBox{Env: env}
	issuanceStore := issuance.NewStore(pool, box, store)
	certStore := certstore.New(pool, box)
	issueWorker := issuance.NewIssueWorker(issuanceStore, certStore)
	issueWorker.Log = log
	riverClient, err := issuance.NewRiver(pool, issueWorker, issuanceStore, log)
	if err != nil {
		return fmt.Errorf("river client: %w", err)
	}
	// Started with a context independent of the shutdown signal: cancelling
	// the context passed to Start aborts running jobs immediately (river's
	// contract), which would race the graceful drain stopRiver performs below.
	if err := riverClient.Start(context.Background()); err != nil {
		return fmt.Errorf("start river: %w", err)
	}
	defer stopRiver(riverClient, log)
	aud := audit.New(pool)
	issuanceSvc := issuance.NewService(issuanceStore, certStore, riverClient)
	issuanceSvc.Auditor = aud
	issuanceSvc.Log = log
	sessions := authn.NewSessions(q, authn.DefaultSessionTTL)
	handler := api.NewRouter(api.Deps{
		Config: cfg, Log: log, Pool: pool, Queries: q, Settings: store, Sections: sections,
		Meta: metaReg, Sessions: sessions, Auditor: aud, Setup: setup.New(pool, aud, sections),
		Issuance: issuanceSvc, Certs: certStore, AuthSettings: authSettings,
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

// stopRiver lets running jobs finish for 30 s, then cancels them; a
// cancelled issuance is recorded as failed and retried after backoff.
func stopRiver(c *river.Client[pgx.Tx], log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Stop(ctx); err != nil {
		log.Warn("river did not stop in time; cancelling running jobs", "err", err)
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		if cancelErr := c.StopAndCancel(cctx); cancelErr != nil {
			log.Error("river did not cancel running jobs cleanly; process is exiting with jobs still in flight",
				"err", cancelErr, "jobs_still_running", riverRunningJobs(context.Background(), c))
		}
	}
}

// riverRunningJobs best-effort counts jobs still in the running state, for
// the shutdown error log above. -1 means the count itself could not be
// fetched (for example the database is unreachable, which is also why
// StopAndCancel above likely failed).
func riverRunningJobs(ctx context.Context, c *river.Client[pgx.Tx]) int {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := c.JobList(ctx, river.NewJobListParams().States(rivertype.JobStateRunning).First(10_000))
	if err != nil {
		return -1
	}
	return len(res.Jobs)
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
