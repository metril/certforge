package agents

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// Kind classifies an Error for the HTTP layer.
type Kind int

// Error kinds.
const (
	KindNotFound Kind = iota + 1
	KindConflict
	KindInvalid
	KindUnauthorized
)

// Error is a failure the caller can act on; the API maps Kind to a status.
type Error struct {
	Kind   Kind
	Field  string // for KindInvalid
	Detail string
}

func (e *Error) Error() string { return e.Detail }

func notFound(format string, a ...any) error {
	return &Error{Kind: KindNotFound, Detail: fmt.Sprintf(format, a...)}
}

func conflict(format string, a ...any) error {
	return &Error{Kind: KindConflict, Detail: fmt.Sprintf(format, a...)}
}

func invalid(field, format string, a ...any) error {
	return &Error{Kind: KindInvalid, Field: field, Detail: fmt.Sprintf(format, a...)}
}

func unauthorized(format string, a ...any) error {
	return &Error{Kind: KindUnauthorized, Detail: fmt.Sprintf(format, a...)}
}

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
