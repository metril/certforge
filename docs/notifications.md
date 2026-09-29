# Notifications

CertForge raises an `Event` for every condition worth telling someone
about — a certificate issued, a renewal that keeps failing, an external
monitor mismatch, a backup outcome — and delivers it to every notification
channel (Settings → Channels, `GET/POST/PATCH/DELETE
/api/v1/orgs/{orgId}/channels`) whose org, event filter and minimum
severity match. `internal/notify` is the event model, the emitter and the
per-channel delivery job; `internal/notify/httpx` is the outbound HTTP
client every HTTP-based notifier (webhook, Discord, ntfy, Home Assistant)
and every external monitor shares. This page covers the event model and
the outbound URL policy; channel configuration and the notifier wire
formats land with Task 4/5's own documentation update.

## Events

`internal/notify.Emit` records one row per condition and fans it out to
every matching channel. Each event has a fixed kind, severity and resource
type — a caller never chooses the severity or resource type itself, only
which kind fired and which resource it is about:

| Kind | Severity | Resource |
|---|---|---|
| `cert.issued` | info | certificate |
| `cert.renewal_failed` | warning | certificate |
| `cert.expiring` | warning | certificate |
| `cert.expired` | critical | certificate |
| `deploy.failed` | warning | grant |
| `deploy.drift` | warning | grant |
| `client.offline` | warning | client |
| `agent.cert_expiring` | warning | client |
| `monitor.mismatch` | critical | monitor |
| `monitor.unreachable` | warning | monitor |
| `monitor.expiring` | warning | monitor |
| `monitor.recovered` | info | monitor |
| `backup.completed` | info | backup |
| `backup.failed` | critical | backup |
| `test` | info | channel |

`backup.*` events carry no `orgId` (a backup is server-wide); every other
kind is scoped to the org whose resource raised it. A channel with
`allOrgs: true` receives every org's events (plus every global one); a
plain org-scoped channel receives its own org's events only — a global
event never reaches an org-scoped channel, however permissive its own
event filter and minimum severity are.

Each channel independently filters what it receives: `events` (empty means
every kind), `minSeverity` (info/warning/critical, inclusive) and its org
scope. A `test` event (`POST
/api/v1/orgs/{orgId}/channels/{id}/test`) is sent to that one channel only,
inline, bypassing the emit/delivery-job path entirely — it never touches
`notification_events`.

## Dedupe

Emit is exact-once per condition: `notification_events.dedupe_key` is
`UNIQUE`, and a second `Emit` call with a key that already fired is a
silent no-op — `(false, nil)`, not an error. The key is built so that the
same underlying condition can never double-fire, but a genuinely new
occurrence of it always can:

| Kind | Dedupe key |
|---|---|
| `cert.issued` | `cert.issued:<versionId>` |
| `cert.renewal_failed` | `cert.renewal_failed:<certId>:<UTC yyyy-mm-dd>` (at most once per day, and only once failures reach the configured threshold) |
| `cert.expiring` | `cert.expiring:<versionId>` |
| `cert.expired` | `cert.expired:<versionId>` |
| `deploy.failed` | `deploy.failed:<grantId>:<versionId>` |
| `deploy.drift` | `deploy.drift:<grantId>:<versionId>` |
| `client.offline` | `client.offline:<clientId>:<last_seen unix>` |
| `agent.cert_expiring` | `agent.cert_expiring:<clientId>:<agent_cert_serial>` |
| `monitor.<state>` | `monitor.<state>:<monitorId>:<fp>:<state_changed_at unix>` |
| `backup.completed` | `backup.completed:<file>` |
| `backup.failed` | `backup.failed:<UTC hour>` |
| `test` | `test:<random uuid>` (never dedupes) |

A monitor's key includes `state_changed_at` (a column added specifically
for this): a `(monitor, state, fingerprint)` key alone would silence every
later episode of the same state forever, since an unreachable monitor has
no fingerprint to vary the key. The state transition itself is a
compare-and-set (`UPDATE ... WHERE state = $old`), so two racing checks of
the same monitor emit the transition exactly once between them.

Emit's own job, beyond the dedupe check, is small: set the severity
(`SeverityOf`), truncate the summary to 500 characters, insert the event
row, then insert one `pending` `notification_deliveries` row and enqueue
one `certforge_notify_deliver` job per matching, enabled channel — all
inside the same transaction (`Emit`'s `tx` parameter, nil meaning it opens
and commits its own). A caller that raises an event as part of a larger
write (issuance's own transaction, for instance) passes that transaction
in; if the caller then rolls back, the event, its deliveries and their jobs
all roll back with it — nothing is left half-recorded.

Each delivery is retried independently by river (`certforge_notify_deliver`,
five attempts) with its own `attempts`/`status`/`last_error` on
`notification_deliveries` — a channel failing does not block or retry any
other channel's own delivery of the same event.

## URL policy

Every channel URL (a webhook or Discord `url`, ntfy's `server`, Home
Assistant's `baseUrl`) and every external monitor's `host` is checked
against the same SSRF policy, both when the value is saved
(`httpx.CheckURL`/`CheckHost`) and again immediately before each outbound
request or dial (`httpx.DialControl`, applied to the address a hostname
actually resolved to — closing the DNS-rebinding gap a save-time-only check
would leave open).

By default: `http`/`https` only, no userinfo in the URL, and the resolved
address must not be unspecified (`0.0.0.0`, `::`), multicast, loopback or
link-local (`127.0.0.0/8`, `::1`, `169.254.0.0/16`, `fe80::/10`, and
`localhost` by name) — an IPv4-mapped IPv6 literal (`::ffff:127.0.0.1`) is
classified by its embedded IPv4 address, not treated as an ordinary global
one. Settings → Notifications' **Allow loopback and private URLs**
(`allowLoopbackUrls`, off by default) re-admits loopback and link-local
targets, for a home-lab setup reaching a channel or monitor on the same
host or network. Two addresses stay blocked either way:
`169.254.169.254` and `fd00:ec2::254`, the AWS/GCP/Azure and EC2 IMDSv2
instance-metadata endpoints — letting a channel or monitor reach either
would hand out cloud credentials regardless of how permissive the loopback
setting is.

`httpx.Client` (every HTTP notifier, built on `net/http`) additionally
never follows a redirect (a 3xx response is a failure, not a hop), ignores
proxy environment variables, retries a connection error, a `5xx` or a
`429` up to three times with `200ms·2^n` backoff, and caps a response body
at 64 KiB. TLS verification is never disabled — a channel's `caPem` only
adds trust to the system root pool.
