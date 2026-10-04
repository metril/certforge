//go:build integration

package flow_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/flow"
	"github.com/metril/certforge/internal/issuance"
)

// txTracer records whether each traced query ran inside a transaction.
type txTracer struct {
	mu   sync.Mutex
	inTx map[string]bool
}

func (t *txTracer) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	for _, k := range []string{"FROM cas WHERE", "FROM issuance_defaults", "FROM certificates c", "FROM certificate_versions"} {
		if strings.Contains(d.SQL, k) {
			t.mu.Lock()
			if prev, ok := t.inTx[k]; !ok || prev {
				t.inTx[k] = c.PgConn().TxStatus() == 'T'
			}
			t.mu.Unlock()
		}
	}
	return ctx
}

func (t *txTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// TestBuildReadsInOneTransaction: the CA, certificate page, org defaults and
// version reads of a flow build all run inside the snapshot transaction.
func TestBuildReadsInOneTransaction(t *testing.T) {
	ctx := context.Background()
	base, _ := dbtest.New(t)
	org := dbtest.Org(t, base)
	cfg, err := pgxpool.ParseConfig(base.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	tr := &txTracer{inTx: map[string]bool{}}
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	box := cryptotest.PrefixBox{}
	b := flow.Builder{Pool: pool, Q: sqlcgen.New(pool), Issuance: issuance.NewStore(pool, box, nil), Certs: certstore.New(pool, box)}
	if _, err := b.Build(ctx, org, flow.Perms{}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"FROM cas WHERE", "FROM issuance_defaults", "FROM certificates c"} {
		in, ok := tr.inTx[k]
		if !ok {
			t.Fatalf("query %q never ran", k)
		}
		if !in {
			t.Errorf("query %q ran outside the snapshot transaction", k)
		}
	}
}
