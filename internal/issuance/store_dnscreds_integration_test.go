//go:build integration

package issuance

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/dbtest"
)

// TestListDNSCredentialsBatched checks the batched, org-filtered used-by
// count equals the per-credential CountDNSCredentialUsers (plus the global
// defaults reference) on credentials in two orgs, referenced by a rule, an
// override, both at once, an org default and a global default, and that
// stored secret names come from the plaintext column with a fallback for a
// row written before it existed.
func TestListDNSCredentialsBatched(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	otherOrg := dbtest.Org(t, f.pool)

	mk := func(org uuid.UUID, name string) DNSCredential {
		c, err := f.store.CreateDNSCredential(ctx, org, name, "cloudflare", map[string]string{"CF_DNS_API_TOKEN": "tok"})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	unused, ruled, overridden, both, orgDef, globalRef, otherOrgCred := mk(f.org, "unused"), mk(f.org, "ruled"), mk(f.org, "overridden"),
		mk(f.org, "both"), mk(f.org, "orgdef"), mk(f.org, "globalref"), mk(otherOrg, "other")
	_ = unused

	rule := func(id uuid.UUID) string {
		b, _ := json.Marshal([]map[string]any{{"dnsCredentialId": id.String(), "method": "dns-01"}})
		return string(b)
	}
	ins := func(name string, rules, overrides string, org uuid.UUID) {
		if _, err := f.pool.Exec(ctx, `INSERT INTO certificates (org_id, name, common_name, verification_rules, overrides) VALUES ($1, $2, $2, $3::jsonb, $4::jsonb)`,
			org, name, rules, overrides); err != nil {
			t.Fatal(err)
		}
	}
	ins("c-rule", rule(ruled.ID), `{}`, f.org)
	ins("c-rule2", rule(ruled.ID), `{}`, f.org)
	ins("c-over", `[]`, `{"verificationRules":`+rule(overridden.ID)+`}`, f.org)
	ins("c-both", rule(both.ID), `{"verificationRules":`+rule(both.ID)+`}`, f.org)
	ins("c-junk", `[]`, `{"verificationRules":"not-an-array"}`, f.org)
	ins("c-other", rule(otherOrgCred.ID), `{}`, otherOrg)
	if _, err := f.pool.Exec(ctx, `INSERT INTO issuance_defaults (org_id, config) VALUES ($1, jsonb_build_object('verificationRules', $2::jsonb)) ON CONFLICT (org_id) DO UPDATE SET config = excluded.config`, f.org, rule(orgDef.ID)); err != nil {
		t.Fatal(err)
	}
	g := Defaults{}
	if err := json.Unmarshal([]byte(`{"verificationRules":`+rule(globalRef.ID)+`}`), &g); err != nil {
		t.Fatal(err)
	}
	f.store.global = fakeGlobal{d: g}

	// A row written before stored_secret_keys existed.
	if _, err := f.pool.Exec(ctx, `UPDATE dns_provider_credentials SET stored_secret_keys = '{}' WHERE id = $1`, ruled.ID); err != nil {
		t.Fatal(err)
	}

	for _, org := range []uuid.UUID{f.org, otherOrg} {
		list, err := f.store.ListDNSCredentials(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range list {
			n, err := f.store.q.CountDNSCredentialUsers(ctx, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if ref, _ := f.store.globalDefaultsReference(ctx, c.ID); ref {
				n++
			}
			if c.UsedBy != n {
				t.Errorf("%s: UsedBy = %d, per-row count = %d", c.Name, c.UsedBy, n)
			}
			one, err := f.store.GetDNSCredential(ctx, org, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(one.StoredSecrets, c.StoredSecrets) || len(c.StoredSecrets) != 1 {
				t.Errorf("%s: list names %v, get names %v", c.Name, c.StoredSecrets, one.StoredSecrets)
			}
		}
	}
	want := map[string]int64{"unused": 0, "ruled": 2, "overridden": 1, "both": 1, "orgdef": 1, "globalref": 1}
	list, _ := f.store.ListDNSCredentials(ctx, f.org)
	if len(list) != len(want) {
		t.Fatalf("listed %d credentials", len(list))
	}
	for _, c := range list {
		if c.UsedBy != want[c.Name] {
			t.Errorf("%s: UsedBy = %d, want %d", c.Name, c.UsedBy, want[c.Name])
		}
	}
	// The plaintext column carries names only and is written on create and update.
	var keys []string
	if err := f.pool.QueryRow(ctx, `SELECT stored_secret_keys FROM dns_provider_credentials WHERE id = $1`, both.ID).Scan(&keys); err != nil || !reflect.DeepEqual(keys, []string{"CF_DNS_API_TOKEN"}) {
		t.Fatalf("stored_secret_keys = %v, %v", keys, err)
	}
	if _, _, err := f.store.UpdateDNSCredential(ctx, f.org, ruled.ID, "ruled", map[string]string{"CF_DNS_API_TOKEN": "new"}); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT stored_secret_keys FROM dns_provider_credentials WHERE id = $1`, ruled.ID).Scan(&keys); err != nil || !reflect.DeepEqual(keys, []string{"CF_DNS_API_TOKEN"}) {
		t.Fatalf("after update stored_secret_keys = %v, %v", keys, err)
	}
}
