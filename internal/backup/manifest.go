package backup

// Manifest is every application table this archive format covers, in load
// order: goose_db_version first (its own row is dumped and hash-checked at
// restore, but never loaded back — the migrator owns it, Deviations R6),
// then every table from internal/db/migrations/*.sql in the order its
// CREATE TABLE ran, and no river_* table (river's own schema is out of
// scope for the archive; MigrateTo re-applies it after restore, and
// Restore truncates river_job separately so no stale job survives a
// restore that replaced the rows it pointed at).
//
// TestManifestCoversAllTables is the standing check that this list stays
// exactly information_schema's non-river tables as later phases add more.
var Manifest = []string{
	"goose_db_version",

	// 00001_init.sql
	"orgs", "sites", "users", "sessions", "role_bindings", "settings", "audit_events",

	// 00002_issuance.sql
	"cas", "acme_accounts", "dns_provider_credentials", "issuance_defaults",
	"certificates", "certificate_versions", "issuance_attempts", "manual_dns_pending",

	// 00004_api_keys.sql
	"api_keys",

	// 00008_agents.sql
	"agent_cas", "clients", "enrollment_tokens", "output_specs", "deploy_targets",
	"hooks", "client_cert_grants", "deployments", "hook_runs",

	// 00011_issuance_breadth.sql
	"rate_ledger",

	// 00012_vault_private_ca.sql
	"server_deployments",

	// 00013_ops.sql
	"notification_channels", "notification_events", "notification_deliveries", "external_monitors",

	// 00023_ca_crls.sql
	"ca_crls",

	// 00024_enrollment_approval.sql
	"enrollment_requests",
}

// TableSum is one table's row count and content hash, as recorded in the
// archive's manifest.json tar entry and compared against what Restore
// actually loads.
type TableSum struct {
	Name   string `json:"name"`
	Rows   int64  `json:"rows"`
	SHA256 string `json:"sha256"`
}

// manifestFile is manifest.json's shape: the final tar entry, itself
// encrypted like every other chunk, listing every table's row count and
// content hash so Restore can detect a missing table, a swapped table or a
// row miscount even though the header only lists table names.
type manifestFile struct {
	Tables []TableSum `json:"tables"`
}
