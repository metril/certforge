//go:build integration

// Package dbtest starts one throwaway Postgres 16 container per test binary
// and gives each test its own fresh database.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

var (
	once     sync.Once
	adminURL string
	startErr error
)

func start() {
	ctx := context.Background()
	c, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("certforge"),
		postgres.WithUsername("certforge"),
		postgres.WithPassword("certforge"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		startErr = err
		return
	}
	adminURL, startErr = c.ConnectionString(ctx, "sslmode=disable")
}

// URL creates a fresh, empty database and returns its connection URL.
func URL(t *testing.T) string {
	t.Helper()
	once.Do(start)
	if startErr != nil {
		t.Fatalf("start postgres container: %v", startErr)
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "t_" + hex.EncodeToString(suffix)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// Empty opens a pool on a fresh database without running migrations.
func Empty(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), URL(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// New opens a pool on a fresh, fully migrated database.
func New(t *testing.T) (*pgxpool.Pool, *sqlcgen.Queries) {
	t.Helper()
	pool := Empty(t)
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool, sqlcgen.New(pool)
}
