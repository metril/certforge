//go:build integration

package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// A statement cut off by the audit query timeout (SQLSTATE 57014) is a 422
// asking the caller to narrow the search, not a 500.
func TestAuditReadTimeoutIs422(t *testing.T) {
	pool, q := dbtest.New(t)
	s := &Server{d: Deps{Pool: pool, Queries: q, AuditQueryTimeout: 50 * time.Millisecond}}
	err := s.auditRead(context.Background(), func(tx pgx.Tx, _ *sqlcgen.Queries) error {
		_, err := tx.Exec(context.Background(), "SELECT pg_sleep(2)")
		return err
	})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusUnprocessableEntity {
		t.Fatalf("err = %v", err)
	}
}
