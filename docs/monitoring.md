# Monitoring

External TLS monitors (Settings → Monitors) arrive in Phase 6A Task 9; this document's `#external-monitors` and `#states` sections land with it.

## Prometheus {#prometheus}

`GET /metrics` (not under `/api/v1`, outside the OpenAPI document — see [api.md](api.md)) is a Prometheus scrape target, gated by Settings → Prometheus:

- `enabled` (default off). While off, the route is `404`.
- `bearerToken` (16–256 characters), required once `enabled` is on, the same "required when enabled" rule Settings → SMTP applies to its password. Generate one with, for example, `openssl rand -hex 32`.

Once enabled, every scrape must send `Authorization: Bearer <token>`; a missing or wrong token gets `401` with an empty body and `WWW-Authenticate: Bearer` (constant-time compared, so a wrong token never leaks timing information about how much of it was right). See [security.md#metrics-token](security.md#metrics-token).

Example Prometheus scrape config:

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

## Metrics reference {#metrics-reference}

Series with a `route` label use chi's own route pattern (`/api/v1/orgs/{orgId}/certificates`, never a request's actual org id), so their cardinality is bounded by the number of API routes, not by traffic. `certforge_certificate_not_after_seconds` is the one series labelled by an id (`certificate`) rather than a name or slug — its cardinality scales with the number of certificates, which is the one place that trade-off is unavoidable (a certificate's own not-after has no other useful grouping). Every other label (`org`, `status`, `state`, `kind`, `result`, `type`) is a small, fixed set of values.

| Series | Type | Labels | Meaning |
|---|---|---|---|
| `certforge_certificates` | gauge | `org`, `status` | Certificates by organization and status. |
| `certforge_certificate_not_after_seconds` | gauge | `org`, `certificate` | Current version expiry (unix seconds) of each certificate that has an issued version. |
| `certforge_certificates_due_renewal` | gauge | `org` | Managed certificates whose next renewal is now or past due. |
| `certforge_issuance_attempts_total` | counter | `result` (`success`\|`failed`) | Certificate issuance attempts by outcome. |
| `certforge_issuance_duration_seconds` | histogram | — | Issuance attempt duration. |
| `certforge_clients` | gauge | `org`, `status` (`online`\|`offline`\|`pending`\|`revoked`) | Agent clients by status. `online` is `active` and seen within Settings → Agents → offline after; `offline` is `active` but stale. |
| `certforge_deployments` | gauge | `org`, `status` (`pending`\|`ok`\|`failed`\|`drift`) | Certificate deployments (agent- and server-run grants alike) by status. |
| `certforge_notifications_total` | counter | `type`, `result` (`delivered`\|`failed`) | Notification delivery attempts by channel type and outcome (Phase 6A Task 3+). |
| `certforge_monitor_checks_total` | counter | `result` | External monitor checks by resulting state (Phase 6A Task 9). |
| `certforge_monitors` | gauge | `org`, `state` | External monitors by state (Phase 6A Task 9). |
| `certforge_river_jobs` | gauge | `kind`, `state` | Non-completed river jobs by kind and state. |
| `certforge_backup_last_success_timestamp_seconds` | gauge | — | Unix time of the last successful backup; `0` if none has ever completed (Phase 6A Task 12). |
| `certforge_kek_rewrap_remaining` | gauge | — | Sealed columns still on a non-active KEK, from the most recent rewrap run. |
| `certforge_build_info` | gauge | `version` | Always `1`; labelled with the running server's version. |
| `certforge_http_requests_total` | counter | `route`, `method`, `status` | HTTP requests, main listener only. |
| `certforge_http_request_duration_seconds` | histogram | `route` | HTTP request duration, main listener only. |

Standard Go runtime (`go_*`) and process (`process_*`) collectors are included too. Everything is served from a dedicated registry — nothing registered elsewhere in the process leaks into the scrape.

The database-backed series above are refreshed at most once every 15 seconds: a scrape more often than that reuses the previous snapshot rather than re-querying.
