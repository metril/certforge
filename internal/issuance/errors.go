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
type InUseError struct {
	Users int64
	// Reason, when set, replaces the generic message.
	Reason string
}

func (e *InUseError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return fmt.Sprintf("still referenced by %d certificates, accounts or defaults", e.Users)
}

// ConflictError is a 409: a write collides with existing state (a
// certificate name already used by an upload) or a certificate's managed
// state blocks the operation (uploading a version onto a certificate
// CertForge still issues and renews itself).
type ConflictError struct{ Msg string }

func (e *ConflictError) Error() string { return e.Msg }

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
