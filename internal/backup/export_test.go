package backup

import (
	"context"
	"io"

	"github.com/jackc/pgx/v5"
)

// WriteWithRootForTest exposes writeTx with an explicit rootSealed
// override, for write_restore_integration_test.go's
// TestRestoreRootMismatchRollsBack: since Write now always reads
// crypto.root live from its own snapshot transaction (batch-4 review,
// Critical), producing an archive whose header disagrees with its own
// dumped settings.csv row is no longer possible through Write itself —
// this hook simulates a hand-crafted or buggy archive instead, so that
// test still proves restoreLoad's own root-consistency check is real
// defense in depth, not merely an invariant Write happens to uphold.
func WriteWithRootForTest(ctx context.Context, tx pgx.Tx, w io.Writer, opts WriteOpts, rootSealed []byte) (Summary, error) {
	return writeTx(ctx, tx, w, opts, rootSealed)
}

// WriteWithTablesForTest writes an archive covering only tables, as an
// older build with a shorter Manifest would have.
func WriteWithTablesForTest(ctx context.Context, tx pgx.Tx, w io.Writer, opts WriteOpts, rootSealed []byte, tables []string) (Summary, error) {
	return writeTxTables(ctx, tx, w, opts, rootSealed, tables)
}
