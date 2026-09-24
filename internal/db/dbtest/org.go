//go:build integration

package dbtest

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Org inserts an org with a random slug and returns its id (plan 1B).
func Org(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	slug := "org-" + uuid.NewString()[:8]
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO orgs (slug, name) VALUES ($1, $1) RETURNING id`, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
