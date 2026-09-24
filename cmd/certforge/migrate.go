package main

import (
	"context"
	"fmt"
	"io"

	"github.com/metril/certforge/internal/db"
)

func runMigrate(ctx context.Context, _ []string, stdout io.Writer) error {
	_, log, pool, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	v, err := db.Version(ctx, pool)
	if err != nil {
		return err
	}
	log.Info("migrations applied", "version", v)
	fmt.Fprintf(stdout, "schema version %d\n", v)
	return nil
}
