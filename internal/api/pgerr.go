package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
)

// conflict builds a 409 HTTPError.
func conflict(format string, a ...any) error {
	return &HTTPError{Status: http.StatusConflict, Title: "Conflict", Detail: fmt.Sprintf(format, a...)}
}

// pgForeignKeyViolation is Postgres error code 23503.
const pgForeignKeyViolation = "23503"

// pgCode returns err's Postgres SQLSTATE code, or "" when err isn't one.
func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
