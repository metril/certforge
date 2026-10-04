# Monitoring

## External monitors

An external monitor polls a TLS endpoint on a schedule — independent of whether CertForge itself deployed anything there — and raises an event on `monitor.mismatch`, `monitor.unreachable`, `monitor.expiring` or `monitor.recovered` (see [notifications.md](notifications.md)). `POST/GET/PATCH/DELETE /orgs/{orgId}/monitors` needs `alerts:read` (list/get) or `alerts:write` (create/update/delete); at most 500 per org. Deleting a certificate that a monitor expects (`expectedCertId`) is refused with 409 naming those monitors; change or delete them first.

Fields (`MonitorInput`):

- `name` (1–100 characters, unique in the org).
- `host` (hostname or literal IP, ≤ 253 characters) and `port` (default `443`). `host` follows the same loopback/link-local policy as a notification channel's URL (Settings → Notifications → "Allow loopback/private URLs"; see [notifications.md#url-policy](notifications.md#url-policy)) — a loopback or link-local address is refused unless that setting is on (cloud-metadata addresses are always refused), while RFC 1918 private-network addresses are allowed (see [security.md](security.md)).
- `sni` (optional; defaults to `host`) — the TLS server name to send, for a host that serves more than one certificate by SNI.
- `intervalSeconds` (300–86400, default `3600`) — how often the scheduled scan checks this monitor.
- `expectedCertificateId` (optional) — a certificate already managed by this org. The mismatch check always runs: with `expectedCertificateId` set, the presented leaf's fingerprint must match that certificate's *current version*; omitted or null does not skip the check — instead the leaf must match the current version of *some* certificate in the org, so a monitor pointed at a host CertForge does not manage anything for will read as `mismatch` unless `expectedCertificateId` is set to name it.

A check dials `host:port` with a 10 second timeout, sends `sni` (or `host`) as the TLS `ServerName`, and captures whatever leaf certificate is presented — the handshake itself never fails on an untrusted or mismatched chain (`InsecureSkipVerify`, capture-only); the observed leaf is then compared against the system trust store *separately*, and that result (if any) travels in the resulting event's `details.chainError`, never as its own state.

`POST /orgs/{orgId}/monitors/{id}/check` (`alerts:write`) runs one check immediately, inline, bounded to 15 seconds, and returns the updated monitor — useful right after creating or editing one, instead of waiting for the next scheduled pass. The scheduled scan itself runs every minute and enqueues a check for every enabled monitor whose `nextCheckAt` is due; each check then reschedules itself `intervalSeconds` (plus up to 10% jitter, to avoid a fleet of monitors sharing an interval all re-checking on the same tick) after `now`.

Editing `host`, `port`, `sni` or `expectedCertificateId` resets `state` to `unknown` and `nextCheckAt` to now, so the change is observed on the very next scan rather than waiting out whatever was left of the old interval.

## States

| State | Meaning |
|---|---|
| `unknown` | No check has completed yet (just created, or just edited in a way that resets state — see above). |
| `ok` | Reachable; the leaf matches `expectedCertificateId`'s current version, or — when unset — the current version of some certificate in the org; and does not expire within 14 days. |
| `mismatch` | Reachable, but the leaf's fingerprint does not match `expectedCertificateId`'s current version, or — when unset — does not match any certificate's current version in the org. |
| `expiring` | Reachable and matching (as `ok` defines matching), but the leaf expires within 14 days. |
| `unreachable` | The dial or TLS handshake failed (refused, timed out, or the host policy rejected it), or no certificate was presented. |

State order on a conflict between conditions is `unreachable` > `mismatch` > `expiring` > `ok` — an unreachable host is reported as such even if it happens to also be within its expiry window from the last successful check, and a mismatch is reported ahead of an otherwise-fine expiry. An event fires only on a genuine transition (the new state differs from the old, and the write actually won a race against a concurrent check of the same monitor — see [notifications.md#dedupe](notifications.md#dedupe)); `monitor.recovered` fires only when the *previous* state was `mismatch`, `expiring` or `unreachable` and the new one is `ok` — moving from `unknown` straight to `ok` (a monitor's first-ever successful check) is not itself a "recovery" and raises no event.

## Prometheus

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

## Metrics reference

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
| `certforge_audit_head_id` | gauge | — | Id of the newest audit event written or verified by this process. Set to the real head at startup (0 only for an empty table). Alert on `resets(max(certforge_audit_head_id > 0)[1d:5m]) > 0` (the `> 0` ignores a restart's brief 0): a drop means the audit table was rolled back or truncated. |
| `certforge_http_requests_total` | counter | `route`, `method`, `status` | HTTP requests, main listener only. |
| `certforge_http_request_duration_seconds` | histogram | `route` | HTTP request duration, main listener only. |

Standard Go runtime (`go_*`) and process (`process_*`) collectors are included too. Everything is served from a dedicated registry — nothing registered elsewhere in the process leaks into the scrape.

The database-backed series above are refreshed at most once every 15 seconds: a scrape more often than that reuses the previous snapshot rather than re-querying.
