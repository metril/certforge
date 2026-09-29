package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/settings"
)

// runRestore restores an encrypted backup archive (internal/backup.Restore)
// from --in. Without --yes it only reads and prints the archive's plaintext
// header, then exits 2 without touching the database at all — the operator
// confirmation step the CLI row requires. With --yes it takes the exclusive
// restore lock (ErrServerRunning if a server is running), refuses a target
// whose audit_events table is not empty, restores, and appends
// restore.completed to the audit chain with the cli actor, keyed with the
// audit key derived from the just-restored root (task-11-brief).
func runRestore(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	in := flags.String("in", "", "input archive path, or - for stdin")
	yes := flags.Bool("yes", false, "confirm and actually run the restore")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("--in is required")
	}

	r, closeIn, err := openRestoreInput(*in)
	if err != nil {
		return err
	}
	defer closeIn()

	// headerBuf captures exactly the bytes ReadHeader consumed (Magic, the
	// length prefix and the header JSON), so they can be replayed ahead of
	// the rest of r into backup.Restore, which reads its own header again
	// from the very start of the stream. This lets --in - work from stdin:
	// the header is never read twice from the underlying reader.
	var headerBuf bytes.Buffer
	header, err := backup.ReadHeader(io.TeeReader(r, &headerBuf))
	if err != nil {
		return err
	}
	full := io.MultiReader(&headerBuf, r)

	if !*yes {
		fmt.Fprintf(stdout, "archive createdAt=%s appVersion=%s migrationVersion=%d activeKekId=%s\n",
			header.CreatedAt, header.AppVersion, header.MigrationVersion, header.ActiveKEKID)
		fmt.Fprintln(stdout, "pass --yes to restore; this overwrites every table in the target database")
		return &exitError{code: 2}
	}

	cfg, _, pool, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	release, err := backup.AcquireRestoreLock(ctx, pool)
	if err != nil {
		return err
	}
	defer release()

	empty, err := auditEventsEmpty(ctx, pool)
	if err != nil {
		return fmt.Errorf("check audit_events: %w", err)
	}
	if !empty {
		return errors.New("restore refuses a target whose audit_events table is not empty; restore into a fresh database")
	}

	active, previousKEKs, _, _, closeKEK, err := buildKEK(ctx, cfg, slog.Default())
	if err != nil {
		return fmt.Errorf("kek: %w", err)
	}
	defer closeKEK()
	env := crypto.NewEnvelope(active, previousKEKs...)

	opts := backup.RestoreOpts{
		Unseal: func(ctx context.Context, sealed []byte) ([]byte, error) {
			var blob crypto.Blob
			if err := blob.Unmarshal(sealed); err != nil {
				return nil, err
			}
			return env.Decrypt(ctx, blob)
		},
		VerifyCanary: func(ctx context.Context, tx pgx.Tx) error {
			var raw []byte
			if err := tx.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.CanaryKey).Scan(&raw); err != nil {
				return err
			}
			var blob crypto.Blob
			if err := blob.Unmarshal(raw); err != nil {
				return err
			}
			pt, err := env.Decrypt(ctx, blob)
			if err != nil {
				return err
			}
			if !bytes.Equal(pt, crypto.CanaryPlaintext) {
				return settings.ErrCanaryMismatch
			}
			return nil
		},
	}

	restored, err := backup.Restore(ctx, pool, full, opts)
	if err != nil {
		return err
	}

	if err := recordRestoreCompleted(ctx, pool, env, restored); err != nil {
		return fmt.Errorf("audit restore.completed: %w", err)
	}

	fmt.Fprintf(stdout, "restore complete: migrationVersion=%d tables=%d\n", restored.MigrationVersion, len(restored.Tables))
	return nil
}

// openRestoreInput opens *in ("-" for stdin, replaceable in tests via the
// package-level stdin var bootstrap_admin.go declares) and returns a
// closer that is a no-op for stdin.
func openRestoreInput(in string) (io.Reader, func(), error) {
	if in == "-" {
		src := stdin
		if src == nil {
			src = os.Stdin
		}
		return src, func() {}, nil
	}
	f, err := os.Open(in)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", in, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// auditEventsEmpty reports whether the target database's audit_events
// table has no rows. A target with no audit_events table at all (a
// genuinely fresh, unmigrated database — the common case) counts as empty:
// db.MigrateTo inside backup.Restore creates it before loading anything.
func auditEventsEmpty(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var reg *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.audit_events')::text`).Scan(&reg); err != nil {
		return false, err
	}
	if reg == nil {
		return true, nil
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_events)`).Scan(&exists); err != nil {
		return false, err
	}
	return !exists, nil
}

// recordRestoreCompleted appends restore.completed as the cli actor, keyed
// with the audit key derived from the just-restored root: restored.RootSealed
// is the exact bytes Restore already proved both unseal under env and equal
// the freshly loaded settings row (Restore's own doc comment), so
// re-unsealing it here yields the restored root's plaintext without
// re-reading it from the database.
func recordRestoreCompleted(ctx context.Context, pool *pgxpool.Pool, env *crypto.Envelope, restored backup.Header) error {
	var blob crypto.Blob
	if err := blob.Unmarshal(restored.RootSealed); err != nil {
		return err
	}
	rootPT, err := env.Decrypt(ctx, blob)
	if err != nil {
		return err
	}
	defer clear(rootPT)
	auditKey := crypto.DeriveKey(rootPT, "certforge-audit")
	aud := audit.New(pool, auditKey)
	return aud.Record(ctx, audit.Event{
		Action: "restore.completed", ResourceType: "backup", ActorType: "cli",
		Details: map[string]any{
			"archiveCreatedAt": restored.CreatedAt,
			"migrationVersion": restored.MigrationVersion,
			"tables":           restored.Tables,
		},
	})
}
