package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/config"
	"github.com/metril/certforge/internal/db"
)

// openDeps loads config, builds the logger, and opens the database pool.
func openDeps(ctx context.Context) (config.Config, *slog.Logger, *pgxpool.Pool, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.SlogLevel()}))
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return config.Config{}, nil, nil, fmt.Errorf("open database: %w", err)
	}
	return cfg, log, pool, nil
}
