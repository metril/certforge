package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

// writeBackupFile writes the archive to a fresh temp file in path's directory
// (0600, fsynced) and renames it onto path, so a reader never sees a partially
// written archive at the final name, a failed backup leaves no file there at
// all, and a planted file or symlink at a predictable name is never followed.
func writeBackupFile(ctx context.Context, pool *pgxpool.Pool, path string, opts backup.WriteOpts) (backup.Summary, error) {
	var summary backup.Summary
	err := writeFileAtomic(path, func(w io.Writer) (err error) {
		summary, err = backup.Write(ctx, pool, w, opts)
		return err
	})
	return summary, err
}

// writeFileAtomic runs write against a CreateTemp file next to path, fsyncs
// it, renames it onto path and fsyncs the directory. The temp file is removed
// on any failure.
func writeFileAtomic(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := write(f); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("sync %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s to %s: %w", tmp, path, err)
	}
	if err := backup.SyncDir(dir); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
