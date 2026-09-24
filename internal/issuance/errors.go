package issuance

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotFound means the row does not exist in the caller's org.
var ErrNotFound = errors.New("not found")

// ValidationError is a 422 with the offending field.
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

// InUseError blocks deleting something that is still referenced.
type InUseError struct{ Users int64 }

func (e *InUseError) Error() string {
	return fmt.Sprintf("still referenced by %d certificates, accounts or defaults", e.Users)
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func dbErr(err error, field string) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return &ValidationError{Field: field, Msg: "already exists"}
	}
	return notFound(err)
}
