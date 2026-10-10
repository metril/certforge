# Monitoring

CertForge exposes two liveness and readiness endpoints for your orchestrator and a Prometheus endpoint for metrics. To watch the TLS certificates your hosts serve, use external monitors; they are in [Alerts](../guide/alerts.md#external-monitors).

## Health endpoints
Both are unauthenticated and on the HTTP listener.

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | Liveness. Returns `200 {"status":"ok"}` while the process serves HTTP. It does not touch the database. |
| `GET /readyz` | Readiness. Checks the database, the encryption key and, when relevant, Vault and backups. |

`/readyz` returns `200 {"status":"ready","checks":{...}}` when the database and the encryption key pass, and `503 {"status":"unavailable","checks":{...}}` when either fails. Details go to the server log, not the response.

| Check | Values | Appears when |
|---|---|---|
| `database` | `ok`, `failed` | Always. |
| `kek` | `ok`, `failed`, `unknown` | Always. `unknown` means the database ping failed, so the key could not be checked. |
| `vault` | `ok`, `degraded`, `failed` | The encryption key is Vault Transit, or **Settings → Integrations → Vault** has an address. Probed with `sys/health`, cached for 30 s. A Transit failure returns `503`. Any other Vault failure is `degraded` and returns `200`. |
| `backup` | `ok`, `degraded` | **Settings → Backups → Schedule** is not `off`. `degraded` means no successful backup, scheduled or on demand, in 7 days. It never causes `503`. |

`certforge healthcheck` probes `/readyz` on `CF_LISTEN_HTTP` and exits 1 unless it returns `200`. Use it as a container `HEALTHCHECK`.

If the encryption key check fails, the server still starts and answers HTTP, so `/readyz` and your alerts work. It does not write audit events, because rows keyed wrongly would never verify later. Most requests still succeed without an audit row. Downloading a private key fails with `500` instead of releasing a key with no audit trail. Fix `CF_KEK` or `CF_KEK_FILE` and restart. See [Key management](key-management.md).

## Scrape Prometheus
`GET /metrics` is outside `/api/v1`. It is off until you enable it.

1. Open **Settings → Integrations → Prometheus**.
2. Turn on **Enabled** (`enabled`, default off). While off, `/metrics` returns `404`.
3. Set **Bearer token** (`bearerToken`, 16 to 256 characters). It is required while enabled. Generate one with `openssl rand -hex 32`.
4. Add the scrape job:

```yaml
scrape_configs:
  - job_name: certforge
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets: ["certforge.example.com"]
    authorization:
      credentials: "<bearerToken>"
```

A missing or wrong token gets `401` with an empty body and `WWW-Authenticate: Bearer`. The token is stored sealed and compared in constant time.

## Metrics reference
Series with a `route` label use the route pattern (for example `/api/v1/orgs/{orgId}/certificates`), never the actual ids, so cardinality follows the number of routes. HTTP-port routes include the agent routes under `/agent/v1`; the separate agent listener is not counted. `certforge_certificate_not_after_seconds` is the one series labelled by certificate id; its cardinality grows with your certificate count.

| Series | Type | Labels | Meaning |
|---|---|---|---|
| `certforge_certificates` | gauge | `org`, `status` | Certificates by organization and status. |
| `certforge_certificate_not_after_seconds` | gauge | `org`, `certificate` | Expiry (Unix seconds) of the current version of each issued certificate. |
| `certforge_certificates_due_renewal` | gauge | `org` | Managed certificates whose renewal is due now or overdue. |
| `certforge_issuance_attempts_total` | counter | `result` (`success`, `failed`) | Issuance attempts by outcome. |
| `certforge_issuance_duration_seconds` | histogram | none | Issuance attempt duration. |
| `certforge_clients` | gauge | `org`, `status` (`online`, `offline`, `pending`, `revoked`) | Agent clients by status. `online` is active and seen within **Settings → Agents → Offline after (seconds)**; `offline` is active but stale. |
| `certforge_deployments` | gauge | `org`, `status` (`pending`, `ok`, `failed`, `drift`) | Deployments, agent and server grants alike. |
| `certforge_notifications_total` | counter | `type`, `result` (`delivered`, `failed`) | Notification delivery attempts by channel type. |
| `certforge_monitor_checks_total` | counter | `result` | External monitor checks by resulting state. |
| `certforge_monitors` | gauge | `org`, `state` | External monitors by state. |
| `certforge_river_jobs` | gauge | `kind`, `state` | Jobs that are not completed, by kind and state. |
| `certforge_backup_last_success_timestamp_seconds` | gauge | none | Unix time of the last successful backup; `0` if none. |
| `certforge_kek_rewrap_remaining` | gauge | none | Sealed columns still on a non-active key, from the latest re-encryption run. |
| `certforge_build_info` | gauge | `version` | Always `1`, labelled with the running version. |
| `certforge_audit_head_id` | gauge | none | Id of the newest audit event written or verified by this process. |
| `certforge_http_requests_total` | counter | `route`, `method`, `status` | HTTP requests, HTTP listener only. |
| `certforge_http_request_duration_seconds` | histogram | `route` | HTTP request duration, HTTP listener only. |

Standard Go (`go_*`) and process (`process_*`) metrics are included. They are served from a dedicated registry. Database-backed series refresh at most every 15 s.

No metric counts pending enrolments. Watch the **Awaiting approval** card or the `client.pending_approval` event ([Events](../reference/events.md)).

Useful alerts:
- Audit table rolled back or truncated: `resets(max(certforge_audit_head_id > 0)[1d:5m]) > 0`. The `> 0` ignores the brief 0 after a restart.
- Backups stale: `time() - certforge_backup_last_success_timestamp_seconds > 2 * 86400` when the schedule is daily.
- Agents offline: `certforge_clients{status="offline"} > 0`.

## Common problems
**`/metrics` returns 404.** the Prometheus section is off.

**`/metrics` returns 401.** The token is missing or wrong.

**`/readyz` returns 503 with `kek: failed`.** The server is running with the wrong encryption key. See [Key management](key-management.md).

**`/readyz` shows `backup: degraded`.** No backup has succeeded for 7 days. Check **Settings → Backups** and the `backup.failed` event.

## See also
- [Security model](security-model.md#metrics-token), [Troubleshooting](troubleshooting.md), [Alerts](../guide/alerts.md)
