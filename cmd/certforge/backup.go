package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

// runBackup writes one encrypted backup archive (internal/backup.Write) to
// --out. --kek-escrowed is still accepted but does nothing. It never takes the serve/restore advisory lock: a backup
// reads a REPEATABLE READ snapshot and writes nothing, so it may run
// alongside a live server.
func runBackup(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := flags.String("out", "", "output archive path, or - for stdout")
	flags.Bool("kek-escrowed", false, "Deprecated: no longer needed.")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}

	cfg, log, pool, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	active, previousKEKs, _, _, closeKEK, err := buildKEK(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("kek: %w", err)
	}
	defer closeKEK()
	env := crypto.NewEnvelope(active, previousKEKs...)
	store := settings.NewStore(sqlcgen.New(pool), env)

	root, err := store.GetSecret(ctx, settings.RootKey)
	if err != nil {
		return fmt.Errorf("root secret: %w", err)
	}
	defer clear(root)

	prevIDs := make([]string, len(previousKEKs))
	for i, w := range previousKEKs {
		prevIDs[i] = w.ID()
	}
	opts := backup.WriteOpts{
		BaseKey:        crypto.DeriveKey(root, "certforge-backup"),
		KEKID:          active.ID(),
		PreviousKEKIDs: prevIDs,
		AppVersion:     version,
		SpoolDir:       cfg.BackupSpoolDir,
	}

	if *out == "-" {
		_, err := backup.Write(ctx, pool, stdout, opts)
		return err
	}

	summary, err := writeBackupFile(ctx, pool, *out, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "backup written to %s (%d bytes, %d tables)\n", *out, summary.SizeBytes, len(summary.Tables))
	return nil
}

// writeBackupFile writes to <path>.tmp (0600) and renames onto path, so a
// reader never sees a partially written archive at the final name and a
// failed backup leaves no file there at all.
func writeBackupFile(ctx context.Context, pool *pgxpool.Pool, path string, opts backup.WriteOpts) (backup.Summary, error) {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return backup.Summary{}, fmt.Errorf("open %s: %w", tmp, err)
	}
	summary, err := backup.Write(ctx, pool, f, opts)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return backup.Summary{}, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return backup.Summary{}, fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return backup.Summary{}, fmt.Errorf("rename %s to %s: %w", tmp, path, err)
	}
	return summary, nil
}
