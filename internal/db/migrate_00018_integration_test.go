//go:build integration

package db_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func queryStrings(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	sort.Strings(out)
	return out
}

func same(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %v, want (old query) %v", what, got, want)
	}
}

// TestRewrittenGrantQueries00018 runs the pre-00018 form of each rewritten
// array query next to the new one on a fixture with the edge cases: a layout
// with no extras, a layout whose extras include a deleted certificate, a
// grant with no hooks, a grant with no layout, a removed grant and a
// deployment that is current, stale, or stale only through an extra.
func TestRewrittenGrantQueries00018(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	org, other := dbtest.Org(t, pool), dbtest.Org(t, pool)

	mustID := func(sql string, args ...any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	cert := func(name string) (uuid.UUID, uuid.UUID) {
		id := mustID(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, $2, $2) RETURNING id`, org, name)
		v := mustID(`INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der, private_key)
			VALUES ($1, '1', now(), now() + interval '1 day', 'fp', 'ecdsa', '\x00', '\x00') RETURNING id`, id)
		if _, err := pool.Exec(ctx, `UPDATE certificates SET current_version_id = $2 WHERE id = $1`, id, v); err != nil {
			t.Fatal(err)
		}
		return id, v
	}
	a, av := cert("a")
	b, bv := cert("b")
	_, _ = cert("c")
	gone := uuid.New()

	layout := func(o uuid.UUID, name string, extras []uuid.UUID) uuid.UUID {
		return mustID(`INSERT INTO output_specs (org_id, name, extra_cert_ids) VALUES ($1, $2, $3) RETURNING id`, o, name, extras)
	}
	l0 := layout(org, "l0", []uuid.UUID{})
	l1 := layout(org, "l1", []uuid.UUID{b})
	l2 := layout(org, "l2", []uuid.UUID{gone, b})
	lOther := layout(other, "lo", []uuid.UUID{b})
	_ = lOther

	h1 := mustID(`INSERT INTO hooks (org_id, name, phase, argv) VALUES ($1, 'h1', 'pre_deploy', '{x}') RETURNING id`, org)
	h2 := mustID(`INSERT INTO hooks (org_id, name, phase, argv) VALUES ($1, 'h2', 'pre_deploy', '{x}') RETURNING id`, org)
	h3 := mustID(`INSERT INTO hooks (org_id, name, phase, argv) VALUES ($1, 'h3', 'pre_deploy', '{x}') RETURNING id`, org)
	cl := func(n string) uuid.UUID {
		return mustID(`INSERT INTO clients (org_id, name) VALUES ($1, $2) RETURNING id`, org, n)
	}
	grant := func(c uuid.UUID, certID, spec uuid.UUID, hooks []uuid.UUID, removed bool, version uuid.UUID, extras []uuid.UUID) uuid.UUID {
		g := mustID(`INSERT INTO client_cert_grants (client_id, cert_id, output_spec_id, hook_ids, removed_at)
			VALUES ($1, $2, $3, $4, CASE WHEN $5 THEN now() END) RETURNING id`, c, certID, spec, hooks, removed)
		if _, err := pool.Exec(ctx, `INSERT INTO deployments (grant_id, version_id, extra_version_ids) VALUES ($1, $2, $3)`, g, version, extras); err != nil {
			t.Fatal(err)
		}
		return g
	}
	c1, c2, c3, c4, c5 := cl("c1"), cl("c2"), cl("c3"), cl("c4"), cl("c5")
	// current, no extras
	grant(c1, a, l0, []uuid.UUID{}, false, av, []uuid.UUID{})
	// stale: version behind
	grant(c2, a, l0, []uuid.UUID{h1}, false, bv, []uuid.UUID{})
	// current extras (b is current; the deleted extra drops out)
	grant(c3, a, l2, []uuid.UUID{h1, h2}, false, av, []uuid.UUID{bv})
	// stale only through its extras
	grant(c4, a, l1, []uuid.UUID{}, false, av, []uuid.UUID{av})
	// removed grant: never stale, never live
	grant(c5, a, l1, []uuid.UUID{h1}, true, bv, []uuid.UUID{})
	// a grant on the extras layout whose deployment recorded no extras yet
	c6 := cl("c6")
	grant(c6, b, l1, []uuid.UUID{}, false, bv, []uuid.UUID{})

	got, err := q.LiveGrantIDsForExtraCert(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "LiveGrantIDsForExtraCert", uuidStrings(got), queryStrings(t, pool, `SELECT g.id::text FROM client_cert_grants g
		JOIN output_specs o ON o.id = g.output_spec_id
		WHERE g.removed_at IS NULL AND g.client_id IS NOT NULL AND $1::uuid = ANY(o.extra_cert_ids)`, b))
	if got, _ = q.LiveGrantIDsForExtraCert(ctx, a); len(got) != 0 {
		t.Fatalf("a is nobody's extra, got %v", got)
	}

	for _, h := range []uuid.UUID{h1, h2, h3} {
		got, err := q.LiveGrantIDsUsingHook(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		same(t, "LiveGrantIDsUsingHook", uuidStrings(got), queryStrings(t, pool,
			`SELECT id::text FROM client_cert_grants WHERE $1::uuid = ANY(hook_ids) AND removed_at IS NULL AND client_id IS NOT NULL`, h))
	}

	counts, err := q.HookGrantCounts(ctx, []uuid.UUID{h1, h2, h3})
	if err != nil {
		t.Fatal(err)
	}
	gotCounts := []string{}
	for _, r := range counts {
		gotCounts = append(gotCounts, fmt.Sprintf("%s=%d", r.ID, r.Grants))
	}
	sort.Strings(gotCounts)
	same(t, "HookGrantCounts", gotCounts, queryStrings(t, pool, `SELECT h.id::text || '=' || count(g.id)
		FROM hooks h LEFT JOIN client_cert_grants g ON h.id = ANY(g.hook_ids) AND g.removed_at IS NULL
		WHERE h.id = ANY($1::uuid[]) GROUP BY h.id`, []uuid.UUID{h1, h2, h3}))

	for _, o := range []uuid.UUID{org, other} {
		names, err := q.LayoutsListingExtraCert(ctx, sqlcgenLayoutsParams(o, b))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(names)
		same(t, "LayoutsListingExtraCert", names, queryStrings(t, pool,
			`SELECT name FROM output_specs WHERE org_id = $1 AND $2::uuid = ANY(extra_cert_ids)`, o, b))
	}

	deps, err := q.HookDependents(ctx, sqlcgenHookDepsParams(h1, org))
	if err != nil {
		t.Fatal(err)
	}
	gotDeps := []string{}
	for _, d := range deps {
		gotDeps = append(gotDeps, fmt.Sprintf("%s/%s/%v", d.ClientName, d.CertificateName, d.Removing))
	}
	sort.Strings(gotDeps)
	same(t, "HookDependents", gotDeps, queryStrings(t, pool, `SELECT c.name || '/' || ce.name || '/' || (g.removed_at IS NOT NULL)::bool
		FROM client_cert_grants g JOIN clients c ON c.id = g.client_id JOIN certificates ce ON ce.id = g.cert_id
		WHERE $1::uuid = ANY(g.hook_ids) AND EXISTS (SELECT 1 FROM hooks h WHERE h.id = $1::uuid AND h.org_id = $2)
		ORDER BY c.name, ce.name LIMIT 6`, h1, org))

	stale, err := q.StaleDeploymentGrantIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := queryStrings(t, pool, `SELECT g.id::text FROM client_cert_grants g
		JOIN certificates ce ON ce.id = g.cert_id
		JOIN deployments d ON d.grant_id = g.id
		LEFT JOIN output_specs o ON o.id = g.output_spec_id
		WHERE g.removed_at IS NULL AND g.client_id IS NOT NULL AND ce.current_version_id IS NOT NULL
		  AND (d.version_id IS DISTINCT FROM ce.current_version_id
		       OR d.extra_version_ids IS DISTINCT FROM (
		            SELECT COALESCE(array_agg(ec.current_version_id ORDER BY x.ord), '{}'::uuid[])
		            FROM unnest(COALESCE(o.extra_cert_ids, '{}'::uuid[])) WITH ORDINALITY AS x(id, ord)
		            JOIN certificates ec ON ec.id = x.id))`)
	same(t, "StaleDeploymentGrantIDs", uuidStrings(stale), want)
	if len(want) != 3 { // c2 (version), c4 (extras), c6 (no extras recorded)
		t.Fatalf("fixture drifted: %d stale grants, want 3", len(want))
	}
}

// TestRewrittenSubjectQueries00018 covers ListRoleBindingsWithLabels and
// ListAPIKeys: non-UUID and upper-case subjects must neither raise from the
// cast nor match a label, and the org / subject-type filters now applied in
// SQL must select what the Go filters used to.
func TestRewrittenSubjectQueries00018(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	org, other := dbtest.Org(t, pool), dbtest.Org(t, pool)

	uid := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, display_name) VALUES ($1, 'Una')`, uid); err != nil {
		t.Fatal(err)
	}
	var k1, k2 uuid.UUID
	for i, o := range []any{org, nil} {
		id := &k1
		if i == 1 {
			id = &k2
		}
		if err := pool.QueryRow(ctx, `INSERT INTO api_keys (name, prefix, secret_hash, scopes, org_id, created_by)
			VALUES ($1, $2, '\x00', '{certs:read}', $3, $4) RETURNING id`, fmt.Sprintf("key%d", i), fmt.Sprintf("%012x", i+1), o, uid).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	bind := func(st, subject string, o any) {
		if _, err := pool.Exec(ctx, `INSERT INTO role_bindings (subject_type, subject, role, org_id) VALUES ($1, $2, 'viewer', $3)`, st, subject, o); err != nil {
			t.Fatal(err)
		}
	}
	bind("user", uid.String(), org)
	bind("user", uid.String(), nil)
	bind("user", "not-a-uuid", org)
	bind("user", "ADMINS-GROUP", other)
	bind("apikey", k1.String(), org)
	bind("apikey", k2.String(), nil)
	bind("apikey", "also-not-a-uuid", other)
	bind("oidc_group", "platform-team", org)
	bind("oidc_group", uuid.NewString(), other) // uuid-shaped group name: never labelled

	old := func(orgFilter *uuid.UUID, stFilter string) []string {
		return queryStrings(t, pool, `SELECT rb.subject_type || '|' || rb.subject || '|' || COALESCE(rb.org_id::text, '') || '|' ||
			COALESCE(u.display_name, k.name, '')::text
			FROM role_bindings rb
			LEFT JOIN users u ON rb.subject_type = 'user' AND u.id::text = rb.subject
			LEFT JOIN api_keys k ON rb.subject_type = 'apikey' AND k.id::text = rb.subject
			WHERE rb.site_id IS NULL AND ($1::uuid IS NULL OR rb.org_id = $1) AND ($2 = '' OR rb.subject_type = $2)`, orgFilter, stFilter)
	}
	for _, c := range []struct {
		org *uuid.UUID
		st  string
	}{{nil, ""}, {&org, ""}, {&other, ""}, {nil, "user"}, {&org, "apikey"}, {nil, "oidc_group"}} {
		var st *string
		if c.st != "" {
			st = &c.st
		}
		rows, err := q.ListRoleBindingsWithLabels(ctx, sqlcgenBindingsParams(c.org, st))
		if err != nil {
			t.Fatalf("org=%v st=%q: %v", c.org, c.st, err)
		}
		got := []string{}
		for _, r := range rows {
			o := ""
			if r.OrgID != nil {
				o = r.OrgID.String()
			}
			got = append(got, r.SubjectType+"|"+r.Subject+"|"+o+"|"+r.SubjectLabel)
		}
		sort.Strings(got)
		same(t, fmt.Sprintf("ListRoleBindingsWithLabels org=%v st=%q", c.org, c.st), got, old(c.org, c.st))
	}

	for _, f := range []*uuid.UUID{nil, &org, &other} {
		rows, err := q.ListAPIKeys(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		got := []string{}
		for _, r := range rows {
			got = append(got, r.ID.String())
		}
		sort.Strings(got)
		same(t, fmt.Sprintf("ListAPIKeys org=%v", f), got, queryStrings(t, pool,
			`SELECT k.id::text FROM api_keys k JOIN users u ON u.id = k.created_by WHERE $1::uuid IS NULL OR k.org_id = $1`, f))
	}
}

func sqlcgenLayoutsParams(org, cert uuid.UUID) sqlcgen.LayoutsListingExtraCertParams {
	return sqlcgen.LayoutsListingExtraCertParams{OrgID: org, CertID: cert}
}

func sqlcgenHookDepsParams(hook, org uuid.UUID) sqlcgen.HookDependentsParams {
	return sqlcgen.HookDependentsParams{HookID: hook, OrgID: org}
}

func sqlcgenBindingsParams(org *uuid.UUID, st *string) sqlcgen.ListRoleBindingsWithLabelsParams {
	return sqlcgen.ListRoleBindingsWithLabelsParams{OrgID: org, SubjectType: st}
}

// TestMigration00018DownUp checks the down section removes the column and
// both indexes, and a following up restores them.
func TestMigration00018DownUp(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 17); err != nil {
		t.Fatalf("down to 00017: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname IN ('sessions_user_id_idx','output_specs_extra_cert_ids_idx','client_cert_grants_hook_ids_idx')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("indexes after down: %d, %v", n, err)
	}
	if _, err := p.UpTo(ctx, 18); err != nil {
		t.Fatalf("up to 00018: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname IN ('sessions_user_id_idx','output_specs_extra_cert_ids_idx','client_cert_grants_hook_ids_idx')`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("indexes after up: %d, %v", n, err)
	}
}
