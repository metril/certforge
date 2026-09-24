// Package sqlcgen holds the sqlc-generated query and model code for
// internal/db/queries. This file is hand-written (sqlc only writes the
// *.sql.go, db.go, and models.go files) and survives `make generate`; it
// exists solely to give the package a comment, since the generated files
// carry none.
package sqlcgen
