package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agenthub"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/kek"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/metrics"
	"github.com/metril/certforge/internal/monitor"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
	"github.com/metril/certforge/internal/signer/localca"
	"github.com/metril/certforge/internal/signer/vaultpki"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/vault"
)

func runServe(ctx context.Context, _ []string, _ io.Writer) error {
	cfg, log, pool, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	// The serve lock is taken before anything else touches the database
	// (Deviations R6 / global-constraints: "before db.Migrate"), so a
	// restore that starts between the two can never race a migration.
	releaseServeLock, err := backup.AcquireServeLock(ctx, pool)
	if err != nil {
		return fmt.Errorf("serve lock: %w", err)
	}
	defer releaseServeLock()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	q := sqlcgen.New(pool)
	active, previousKEKs, legacyKEKs, kekHealth, closeKEK, err := buildKEK(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("kek: %w", err)
	}
	defer closeKEK()
	env := crypto.NewEnvelope(active, previousKEKs...)
	store := settings.NewStore(q, env)
	keysInfo := kekInfo(cfg, active, previousKEKs)
	// EnsureRoot must run before EnsureCanary (pre-flight ruling): a fresh
	// database has no canary yet either, and a root failure here aborts
	// boot outright (a wrong audit key would fork the chain), unlike a
	// canary failure below, which only degrades /readyz.
	root, err := rootKey(ctx, store, legacyKEKs)
	if err != nil {
		return fmt.Errorf("root secret: %w", err)
	}
	auditKey := crypto.DeriveKey(root, "certforge-audit")
	oidcKey := crypto.DeriveKey(root, "certforge-oidc-state")
	// backupBaseKey feeds backup.Service.Stream (Deviations R6): derived
	// here, before clear(root), the same way auditKey/oidcKey are — Write
	// never sees the plaintext root itself, only this already-derived key.
	// RootSealed is not captured here (batch-4 review, Critical): Write
	// now reads the live crypto.root row itself, inside its own snapshot
	// transaction, so it can never go stale against a KEK rewrap that runs
	// between boot and any later backup.
	backupBaseKey := crypto.DeriveKey(root, "certforge-backup")
	clear(root)
	canaryOK := true
	if err := store.EnsureCanary(ctx); err != nil {
		canaryOK = false
		log.Error("KEK canary check failed; /readyz reports unavailable until the correct KEK is configured",
			"kek_id", env.KEKID(), "kek_source", cfg.KEK.Source, "err", err)
	}
	sections := settings.DefaultRegistry()
	if err := issuance.RegisterSettings(sections); err != nil {
		return err
	}
	if err := issuance.RegisterIssuanceSettings(sections); err != nil {
		return err
	}
	if err := authn.RegisterSettings(sections, cfg.AllowInsecureOIDCIssuer); err != nil {
		return err
	}
	if err := agents.RegisterSettings(sections); err != nil {
		return err
	}
	if err := vault.RegisterSettings(sections); err != nil {
		return err
	}
	if err := notify.RegisterSettings(sections); err != nil {
		return err
	}
	if err := metrics.RegisterSettings(sections); err != nil {
		return err
	}
	// The DB-backed Collector is registered once, here: Registry (a package
	// var) is otherwise only holding the Go/process collectors and the
	// package-level counters/histogram, wired in internal/metrics/metrics.go's
	// own init().
	metrics.Registry.MustRegister(metrics.NewCollector(pool, store, version, log))
	authSettings, err := authn.NewSettingsSource(store, sections)
	if err != nil {
		return err
	}
	metaReg := meta.NewRegistry()
	challenge.AddToMeta(metaReg)
	localca.AddToMeta(metaReg)
	vaultpki.AddToMeta(metaReg)
	// Later phases register settings sections and other pluggable type schemas here.
	box := crypto.EnvelopeBox{Env: env}
	vaultProvider := vault.NewProvider(store, sections, log)
	targetsReg := newTargetsRegistry(vaultProvider)
	targets.AddToMeta(targetsReg, metaReg)
	// notifySettings reads the live "notifications" section on every Send
	// (never cached): notify.SettingsFunc's doc comment.
	notifySettings := func(ctx context.Context) (notify.Settings, error) { return notify.Current(ctx, store) }
	notifyReg := notify.NewRegistry()
	notifyReg.Register(notify.Webhook{Settings: notifySettings})
	notifyReg.Register(notify.Discord{Settings: notifySettings})
	notifyReg.Register(notify.Ntfy{Settings: notifySettings})
	notifyReg.Register(notify.HomeAssistant{Settings: notifySettings})
	notifyReg.Register(notify.SMTP{Settings: func(ctx context.Context) (notify.SMTPSettings, string, error) {
		return notify.CurrentSMTP(ctx, store, sections)
	}})
	notify.AddToMeta(notifyReg, metaReg)
	// notifyEmitter is shared by notifySvc, notifySources, monitorSvc and
	// backupSvc below: one *notify.Emitter, one river.Inserter. River is
	// nil until riverClient exists (set right after, same
	// construct-then-wire order as keysSvc/dispatcher above); Emit's own
	// nil-tx path only needs Pool until then, and nothing calls Emit before
	// riverClient.Start.
	notifyEmitter := &notify.Emitter{Pool: pool, Log: log}
	// notifySources is issueWorker's third Listener (OnVersion) and its
	// OnFailure hook below, plus the hourly certforge_notify_scan job
	// (RegisterRiver): cert.issued/cert.renewal_failed synchronously, the
	// rest (expiring/expired, deploy, offline, agent-cert-expiring, prune)
	// on the scan.
	notifySources := &notify.Sources{Q: q, Emitter: notifyEmitter, Settings: store, Log: log}
	monitorSvc := &monitor.Service{Store: &monitor.Store{Pool: pool, Q: q}, Emitter: notifyEmitter, Settings: store}
	issuanceStore := issuance.NewStore(pool, box, store)
	issuanceStore.SetVault(vaultProvider)
	certStore := certstore.New(pool, box)
	// dispatcher.River is set right after riverClient exists below (same
	// construct-then-wire order as keysSvc): RegisterRiver only needs the
	// Dispatcher pointer, not River itself, to register DeployWorker.
	// HTTP reads the live "notifications" allowLoopbackUrls setting on
	// every deploy (never cached), same as notifySettings above and
	// monitorAllowLoopback (internal/api/monitors.go); a settings read
	// failure denies loopback rather than silently allowing it.
	dispatcher := &deploy.Dispatcher{Pool: pool, Q: q, Reg: targetsReg, Certs: certStore, Box: box,
		HTTP: func(ctx context.Context) targets.HTTPFactory {
			st, err := notifySettings(ctx)
			return targets.HTTPFactory{AllowLoopback: err == nil && st.AllowLoopbackURLs}
		},
		// Events: an immediate deploy.failed on every failed server-run
		// attempt (task-7 brief), deduping with notifySources' hourly
		// ScanFailedServerDeployments backstop through the same DedupeKey.
		// notifyEmitter already exists at this point (constructed above,
		// before dispatcher); this is the one place internal/deploy's
		// Events interface is bound to internal/notify's implementation,
		// keeping internal/deploy itself free of any notify import.
		Events: notify.DeployEvents{E: notifyEmitter}, Log: log}
	agentSettings, err := agents.NewSettingsSource(store, sections, cfg.BaseURL)
	if err != nil {
		return err
	}
	agentCA := agentca.NewStore(pool, box)
	// A failed canary means the KEK cannot be trusted to be the one this
	// database was set up with: constructing a recording Auditor with
	// auditKey would write rows keyed wrong, which Rechain and Check can
	// never verify (ADR 0008). NewDisabled refuses every Record call
	// instead; readiness already reports the KEK failure separately.
	aud := audit.New(pool, auditKey)
	if !canaryOK {
		aud = audit.NewDisabled(pool, auditKey)
	}
	if canaryOK {
		if n, err := aud.Rechain(ctx); err != nil {
			log.Error("audit chain not re-keyed; GET /api/v1/audit/verify reports where it breaks", "err", err)
		} else if n > 0 {
			log.Info("audit chain re-keyed with HMAC-SHA256", "events", n)
		}
	}
	notifySvc := &notify.Service{
		Store: &notify.Store{Pool: pool, Q: q}, Emitter: notifyEmitter, Registry: notifyReg,
		Box: box, Settings: store, Audit: aud, BaseURL: cfg.BaseURL, Version: version, Log: log,
	}
	agentListener := &agentca.Listener{Source: agentCA, Log: log, Names: func(ctx context.Context) ([]string, error) {
		st, err := agentSettings.Get(ctx)
		return st.Names(), err
	}}
	agentSvc := &agents.Service{Pool: pool, Q: q, CA: agentCA, Certs: certStore, Box: box, Auditor: aud, Settings: agentSettings, Log: log, Reg: targetsReg}
	agentSvc.OnPendingApproval = func(ctx context.Context, e agents.PendingApproval) {
		_, err := notifyEmitter.Emit(ctx, nil, notify.Event{Kind: "client.pending_approval", OrgID: &e.OrgID,
			Resource:  notify.Resource{ID: e.ClientID.String(), Name: e.ClientName},
			Summary:   fmt.Sprintf("%s is waiting for enrolment approval", e.ClientName),
			Details:   map[string]any{"verifyCode": e.VerifyCode, "hostname": e.Hostname, "expiresAt": e.ExpiresAt},
			DedupeKey: "client.pending_approval:" + e.RequestID.String()})
		if err != nil {
			log.Error("notify: client.pending_approval emit failed", "err", err)
		}
	}
	issueWorker := issuance.NewIssueWorker(issuanceStore, certStore)
	issueWorker.Log = log
	issueWorker.Listeners = append(issueWorker.Listeners, agentSvc, dispatcher, notifySources)
	// OnFailure hangs off issueWorker only (Deviations R2): a version
	// upload/import path has no comparable failure to report. Set before
	// riverClient.Start, same as every other worker field below.
	issueWorker.OnFailure = notifySources
	// Shared with api.Deps.HTTPTokens below; set on the worker before
	// riverClient.Start so a server http-01 rule can already be served by
	// the time the first job runs.
	httpTokens := challenge.NewHTTPTokens(0)
	issueWorker.HTTPTokens = httpTokens
	// CAA and Settings back the caa step: a fresh DNS lookup per attempt and
	// the global "issuance" section (caaCheck, rate limits) reloaded fresh
	// each time so a settings change takes effect on the next attempt
	// without a restart. Set before riverClient.Start, same as HTTPTokens.
	issueWorker.CAA = issuance.DNSCAAResolver{}
	issueWorker.Settings = func(ctx context.Context) (issuance.IssuanceSettings, error) {
		return issuance.LoadIssuanceSettings(ctx, store)
	}
	// The ARI poll worker: post-issuance (issueWorker.ARI) and the 6-hourly
	// periodic job NewRiver registers. Its fields are all set here, before
	// riverClient.Start, same as issueWorker's own.
	ariWorker := issuance.NewARIPollWorker(issuanceStore, certStore)
	ariWorker.Log = log
	issueWorker.ARI = ariWorker
	// SignerFactory is the single signer-construction path both workers use
	// (localca, vaultpki and acme cases): wired to both before
	// riverClient.Start, same as HTTPTokens/Relay/CAA/Settings above.
	signerFactory := &issuance.SignerFactory{Store: issuanceStore, Vault: vaultProvider, BaseURL: generalBaseURL(store, cfg.BaseURL)}
	issueWorker.NewSigner = signerFactory.New
	ariWorker.NewSigner = signerFactory.New
	// keysSvc.River is set right after riverClient exists below (same
	// construct-then-wire order as issuanceSvc): RegisterRiver only needs
	// the Service pointer, not River itself, to register RewrapWorker.
	keysSvc := &kek.Service{Env: env, Settings: store, Pool: pool, Audit: aud, Info: keysInfo, Log: log}
	previousKEKIDs := make([]string, len(keysInfo.Previous))
	for i, r := range keysInfo.Previous {
		previousKEKIDs[i] = r.KEKID
	}
	backupSvc := &backup.Service{
		Pool: pool, Settings: store, Audit: aud, Log: log, Emitter: notifyEmitter,
		BaseKey: backupBaseKey, KEKID: env.KEKID(),
		PreviousKEKIDs: previousKEKIDs, AppVersion: version, SpoolDir: cfg.BackupSpoolDir,
	}
	riverClient, err := issuance.NewRiver(pool, issueWorker, ariWorker, issuanceStore, log,
		agentListener.RegisterRiver, agentSvc.RegisterRiver, keysSvc.RegisterRiver, dispatcher.RegisterRiver,
		notifySvc.RegisterRiver, notifySources.RegisterRiver, monitorSvc.RegisterRiver, backupSvc.RegisterRiver)
	if err != nil {
		return fmt.Errorf("river client: %w", err)
	}
	keysSvc.River = riverClient
	dispatcher.River = riverClient
	// notifyEmitter.River completes the shared Emitter (its own doc comment
	// above): notifySvc/notifySources/monitorSvc/backupSvc all already hold
	// this pointer, so this single assignment finishes wiring every one of
	// them before riverClient.Start below.
	notifyEmitter.River = riverClient
	issuanceSvc := issuance.NewService(issuanceStore, certStore, riverClient)
	issuanceSvc.Auditor = aud
	issuanceSvc.Log = log
	// Final review finding 5: a rename also re-enqueues the renamed
	// certificate's own live server grants (agentSvc's hook only re-renders
	// agent-run grants), composed into one RenameHook so both commit inside
	// UpdateCertificate's own transaction and both nudges run after it
	// commits.
	issuanceSvc.RenameHook = func(ctx context.Context, q *sqlcgen.Queries, certID uuid.UUID) (func(), error) {
		agentNudge, err := agentSvc.ResyncCertificateRename(ctx, q, certID)
		if err != nil {
			return nil, err
		}
		deployNudge, err := dispatcher.ResyncCertificateRename(ctx, q, certID)
		if err != nil {
			return nil, err
		}
		return func() {
			if agentNudge != nil {
				agentNudge()
			}
			if deployNudge != nil {
				deployNudge()
			}
		}, nil
	}
	// Same listener as issueWorker.Listeners above: an uploaded version
	// (Task 13) re-renders any grant already on the certificate exactly
	// like a freshly issued one does.
	issuanceSvc.Listeners = append(issuanceSvc.Listeners, agentSvc, dispatcher)
	// Backs UploadVersion's keyless-grant rule (fix round 1); see
	// issuance.Service.KeylessGrantHook and agents.LiveGrantsNeedKeyTx's own
	// doc comments for why this is wired through a closure binding
	// targetsReg, rather than as a plain function value.
	issuanceSvc.KeylessGrantHook = func(ctx context.Context, q *sqlcgen.Queries, certID uuid.UUID) (bool, error) {
		return agents.LiveGrantsNeedKeyTx(ctx, q, targetsReg, certID)
	}
	// Started with a context independent of the shutdown signal: cancelling
	// the context passed to Start aborts running jobs immediately (river's
	// contract), which would race the graceful drain stopRiver performs below.
	// River's RunOnStart scan and issue jobs must not run before agentSvc,
	// issueWorker.Listeners and the hub are wired, or a version issued in
	// that window never reaches deployments and the field writes race.
	agentSvc.Listener = agentListener
	hub := agenthub.New(log)
	agentSvc.Hub = hub
	// agentSvc implements challenge.AgentRelay: an agent-mode http-01 or
	// tls-alpn-01 rule relays Present/CleanUp through it. Set before
	// riverClient.Start, same as HTTPTokens above.
	issueWorker.Relay = agentSvc
	if err := riverClient.Start(context.Background()); err != nil {
		return fmt.Errorf("start river: %w", err)
	}
	defer stopRiver(riverClient, log)
	// Best-effort: a rewrap job is only enqueued when there is previous-KEK
	// data to move or the active KEK can rewrap in place (EnqueueIfNeeded's
	// own check); a failure here never blocks boot the way a KEK or root
	// failure above does.
	if _, err := keysSvc.EnqueueIfNeeded(ctx); err != nil {
		log.Error("kek rewrap not enqueued at boot", "err", err)
	}
	sessions := authn.NewSessions(q, authn.DefaultSessionTTL)
	oidcClient := authn.NewOIDC(oidcKey, nil)
	deps := api.Deps{
		Config: cfg, Log: log, Pool: pool, Queries: q, Settings: store, Sections: sections,
		Meta: metaReg, Sessions: sessions, Auditor: aud, Setup: setup.New(pool, aud, sections),
		Issuance: issuanceSvc, Certs: certStore, Box: box, AuthSettings: authSettings, OIDC: oidcClient,
		Agents: agentSvc, AgentSettings: agentSettings, Hub: hub, AgentListener: agentListener,
		HTTPTokens: httpTokens, Keys: keysSvc, Vault: vaultProvider, Targets: targetsReg, Dispatcher: dispatcher,
		KEKHealth: kekHealth, Version: version, Metrics: metrics.Handler(store, sections), Backup: backupSvc,
		Notify: notifySvc, Monitors: monitorSvc,
	}
	handler := api.NewRouter(deps)
	srv := &http.Server{
		Addr:              cfg.ListenHTTP,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go purgeSessions(ctx, sessions, log)
	errCh := make(chan error, 2)
	go func() {
		log.Info("listening", "addr", cfg.ListenHTTP, "version", version)
		errCh <- srv.ListenAndServe()
	}()
	var agentSrv *http.Server
	if canaryOK {
		if _, err := agentCA.EnsureActive(ctx); err != nil {
			log.Error("agent CA unavailable; the agent listener is not started", "err", err)
		} else if err := agentListener.Reload(ctx); err != nil {
			log.Error("agent listener certificate not issued; the agent listener is not started", "err", err)
		} else {
			agentSrv = &http.Server{
				Addr:              cfg.ListenAgent,
				Handler:           api.NewAgentRouter(deps),
				TLSConfig:         agentListener.TLSConfig(),
				TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			go func() {
				log.Info("agent listener", "addr", cfg.ListenAgent)
				errCh <- agentSrv.ListenAndServeTLS("", "")
			}()
		}
	}
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
	// The agent listener stops accepting new sockets and connections first,
	// before the hub itself shuts down: shutting the hub down first would
	// leave a window where a new agent socket could still be accepted and
	// registered into a hub that is already closing.
	if agentSrv != nil {
		if err := agentSrv.Shutdown(shutdownCtx); err != nil {
			log.Warn("agent listener shutdown", "err", err)
		}
	}
	hub.Shutdown()
	return srv.Shutdown(shutdownCtx)
}

// generalBaseURL mirrors api.Server.baseURL (the General section's base
// URL, else the static fallback) for the issuance workers, which run
// outside any request and so have no *api.Server to call it on.
func generalBaseURL(store *settings.Store, fallback string) func(ctx context.Context) string {
	return func(ctx context.Context) string {
		var g struct {
			BaseURL string `json:"baseUrl"`
		}
		if err := store.Get(ctx, settings.SectionKey("general"), &g); err == nil && g.BaseURL != "" {
			return g.BaseURL
		}
		return fallback
	}
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

// newTargetsRegistry builds the server's deploy target registry: every
// built-in type internal/targets ships (traefik) plus vault-kv, wired to
// vaultProvider — the exact registry runServe wires into both api.Deps and
// deploy.Dispatcher, and what cmd/certforge's own tests (registry_test.go)
// check against, rather than reimplementing the wiring themselves.
func newTargetsRegistry(vaultProvider *vault.Provider) *targets.Registry {
	reg := targets.NewRegistry()
	targets.RegisterBuiltins(reg)
	reg.Register(deploy.VaultKV{Vault: vaultProvider})
	return reg
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
