# Notifications

CertForge raises an `Event` for every condition worth telling someone
about — a certificate issued, a renewal that keeps failing, an external
monitor mismatch, a backup outcome — and delivers it to every notification
channel (Settings → Channels, `GET/POST/PATCH/DELETE
/api/v1/orgs/{orgId}/channels`) whose org, event filter and minimum
severity match. `internal/notify` is the event model, the emitter and the
per-channel delivery job; `internal/notify/httpx` is the outbound HTTP
client every HTTP-based notifier (webhook, Discord, ntfy, Home Assistant)
and every external monitor shares. This page covers the event model, channel
configuration, every notifier's wire format and the outbound URL policy.

## Channels

A notification channel (Settings → Channels) is one delivery destination: a
`type` (`webhook`, `smtp`, `discord`, `ntfy` or `homeassistant`), that
type's own config, an event filter (`events`, empty meaning every kind) and
minimum severity, and an org scope (`allOrgs` widens it to every org's
events, gated to a global admin). `GET /api/v1/meta/schemas`'s `notifiers[]`
lists each type's JSON Schema — `title`, `description` and a `secret: true`
marker per field drive the settings UI's form, tooltips and which fields are
stored encrypted. A field marked secret is never read back: `GET
.../channels/{id}`, `GET .../channels` and every write response report
`storedSecrets` (the secret field names that currently have a value) and a
computed `summary` (≤ 200 characters) — a short, non-secret display line,
never derived from a value that could itself carry a secret:
`url.Hostname()` alone for `webhook` and `homeassistant`'s `baseUrl` (never
the scheme, port, path, query or userinfo — any of which could hold a
token), `"<server host>/<topic>"` for `ntfy`, the fixed string "Discord
webhook" for `discord`, and the `to` recipients joined by `", "` for
`smtp` — instead of the value itself. `POST .../channels/{id}/test` sends a
synthetic `test` event to that one channel only: it does write a
`notification_events` row (dedupe key `test:<random uuid>`) and one
`notification_deliveries` row, the same as a real event, but never goes
through `Emit`/`MatchingChannels` — no other channel ever receives it — and
sends inline, under a 10 s bound, rather than through the async delivery
job, so the caller gets an immediate `delivered`/`failed` `DeliveryResult`
with a `durationMs`. A `test` works on a disabled channel too.

`(*notify.Registry).ValidateConfig(type, cfg)` is every channel write's
single validation entry point: it checks `cfg` — the channel's full
submitted config, secret values included, before they are split out to
encrypted storage — against the type's JSON Schema, then the notifier's own
extra check when it has one (`notify.ConfigChecker`): a credential-looking
header name for `webhook`, `webhookUrl`'s scheme for `discord`, `webhookId`'s
character set for `homeassistant`. Those three checks live in Go rather than
the schema itself, because the field they check is secret and the schema
validator would otherwise echo the rejected value into its own error text.
The outbound URL policy (below) is re-checked at create/update time too,
against the field that determines each type's destination host (`url` for
`webhook`, `webhookUrl` for `discord`, `server` for `ntfy`, `baseUrl` for
`homeassistant`), on top of the re-check every `Send` already does at dial
time — `smtp` has no URL field of its own.

An update's secret fields (schema `secret: true`) accept `__unchanged__` or
may simply be left out of `config` entirely; either keeps the stored value.
An empty string `""` clears it. `type` cannot change once created (422 "type
cannot change"); `name` is unique per org (409 on a duplicate); an org holds
at most 50 channels (422 once reached). `allOrgs: true` — on create or
update, whether or not it is already set — needs a global admin (`admin`
role, or an API key scoped `admin`; 403 "all-orgs channels need a global
admin" otherwise); `listChannels` includes another org's `allOrgs` channel
only when the caller is themselves a global admin. `ntfy`'s `server` and
`homeassistant`'s `baseUrl` are their own type's re-entry field (Vault's own
rule, `docs/security.md`): changing it while that type's one secret field
(`token`, `webhookId`) is kept `__unchanged__`/omitted is a 422 "re-enter the
secret" — the old secret would otherwise silently carry over to what may be
a different destination.

`GET /api/v1/orgs/{orgId}/channels/{id}` and `.../channels` need
`alerts:read`; every other channel operation needs `alerts:write`.

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
scope. A `test` event (`POST /api/v1/orgs/{orgId}/channels/{id}/test`,
above) is sent to that one channel only, inline, bypassing `Emit`/
`MatchingChannels` and the async delivery job — but it is still recorded
like any other event (a `notification_events` row and one
`notification_deliveries` row for that channel).

`GET /api/v1/orgs/{orgId}/events` (`alerts:read`) lists the org's own
events plus every global event, newest first, keyset-paginated by
`(at, id)`: `?cursor=` is the previous page's opaque `nextCursor`, `null`
on the last page. `?kind=` is repeatable (a set; omit for every kind),
`?severity=` is a minimum (the same inclusive rank `minSeverity` uses) and
`?since=` bounds `at`. Each `Event` carries its own `deliveries[]` — one
entry per channel that event matched, with that delivery's `status`,
`attempts`, `lastError` (redacted, like every other channel-facing error
text) and `deliveredAt`.

### Event sources

`cert.issued` and `cert.renewal_failed` fire synchronously, off the
issuance worker itself (`internal/notify.Sources`, an
`issuance.VersionListener` and `issuance.FailureListener`); every other
kind below is found by the hourly `certforge_notify_scan` job
(`RunOnStart`, so a freshly started server catches up immediately),
bounded to 1000 candidates per kind per run:

- **`cert.issued`** fires once a renewal actually commits a new version —
  only from `issueWorker.Listeners` (a certificate's own issuance/renewal
  attempts), never from an uploaded or imported version.
- **`cert.renewal_failed`** fires once a certificate's consecutive failure
  count reaches the `notifications.failureThreshold` setting, at most once
  per UTC calendar day thereafter (so a certificate stuck failing for a
  week alerts once a day, not on every attempt). The failure's cause is
  never sent as-is: `issuance.ClassifyFailure` reduces it to a `class`
  (`acme`, `dns`, `caa`, `rate_limit`, `challenge`, `signer` or
  `internal`), the failed step's name, and, when the CA itself returned
  one, its ACME problem type/status — never a URL or hostname.
- **`cert.expiring`** fires once per certificate version, when that
  version is still the current one and its `notAfter` falls within the
  `notifications.expiryWarningDays` window (default 7 days). A later
  renewal (a new current version) is a fresh condition.
- **`cert.expired`** fires once per certificate version, once its
  `notAfter` has passed and it is still the current version.
- **`deploy.failed`** fires once per (grant, version) pair when a live
  grant's own deployment is in state `failed` — an agent-run grant
  (`deployments.state`) or a server-run grant (`server_deployments.status`,
  which has no drift state of its own). A server-run grant's first failed
  attempt also emits immediately from `deploy.Dispatcher` itself, rather
  than waiting for the next scan; the scan's own pass is only a backstop
  and adds nothing further, since both use the same dedupe key.
- **`deploy.drift`** fires once per (grant, version) pair when a live
  agent-run grant's deployment is in state `drift` (what the agent
  installed no longer matches what was rendered); server-run grants have
  no drift detection (nothing reports installed files back).
- **`client.offline`** fires once per "episode": an active client with at
  least one live grant, last seen longer ago than the agents section's
  `offlineAfterSeconds`. The dedupe key is keyed on the client's own
  `last_seen`, so reconnecting and later going offline again is a new
  episode and alerts again.
- **`agent.cert_expiring`** fires once per agent certificate serial, when
  an active client's own agent certificate expires within 14 days (fixed,
  not operator-configurable — an agent renews its own certificate
  automatically; this only fires when that has stopped working).

`monitor.*` (external monitors) and `backup.*` are their own sources
(`internal/monitor`, `internal/backup`), landing in later Phase 6A tasks.
The scan also prunes `notification_events` rows older than 90 days.

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
12 attempts with exponential backoff: 30 s doubling per attempt, capped at
1 h, so about 5 hours in total before the delivery is marked `failed`) with its own `attempts`/`status`/`last_error` on
`notification_deliveries` — a channel failing does not block or retry any
other channel's own delivery of the same event.

## Webhook payload

Webhook and Home Assistant send the same JSON body (`internal/notify.Payload`):

```json
{
  "id": "5b1e4b0a-...",
  "kind": "cert.expiring",
  "at": "2026-09-29T12:00:00Z",
  "severity": "warning",
  "org": {"id": "8f2c...", "name": "Acme"},
  "resource": {"type": "certificate", "id": "c1a9...", "name": "example.com"},
  "summary": "example.com expires in 7 days",
  "details": {"notAfter": "2026-10-06T00:00:00Z"}
}
```

`org` is `null` for a global event (`backup.*`). `details` only ever holds
the keys `internal/notify/payload.go`'s per-kind allowlist names for that
`kind` — never key material, a KEK id or a Vault address, whatever an
`Event` happened to carry in its own `Details` map.

A webhook request also carries:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `CertForge/<version>` |
| `X-CertForge-Event` | the event's `kind` |
| `X-CertForge-Delivery` | the event's `id` |
| `X-CertForge-Signature` | `sha256=<hex HMAC>`, sent only when the channel has a `signingSecret` — see Signature below |
| `X-CertForge-Timestamp` | unix seconds when the request was signed, sent with the signature headers — see Signature below |
| `X-CertForge-Signature-V2` | `sha256=<hex HMAC>` over `timestamp + "." + body`, sent only when the channel has a `signingSecret` |
| `Authorization` | the channel's `authHeader`, sent verbatim, when set |

Plus any extra `headers` the channel configures (at most 20, name
`^[A-Za-z0-9-]{1,64}$`, value ≤ 1024 characters). A credential-looking name —
`Authorization`, `Cookie`, `Proxy-Authorization`, `Host`, `Content-Type`,
anything starting `X-CertForge-`, or any name containing `token`, `key`,
`secret` or `auth` — is rejected at save time; use `authHeader` for a bearer
token or similar credential instead.

## Signature

When a webhook channel has a `signingSecret` (16–256 characters),
`X-CertForge-Signature` is `sha256=` followed by the lowercase-hex
HMAC-SHA256 of the exact request body, keyed by that secret. Verify it by
recomputing the same HMAC over the raw bytes you received — not a
re-serialized copy; JSON key order or whitespace differences would change
the digest — and comparing in constant time:

```go
mac := hmac.New(sha256.New, []byte(signingSecret))
mac.Write(body) // the raw request body, unparsed
expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
if !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-CertForge-Signature"))) {
    http.Error(w, "bad signature", http.StatusUnauthorized)
    return
}
```

```python
import hashlib, hmac

expected = "sha256=" + hmac.new(signing_secret.encode(), body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers.get("X-CertForge-Signature", "")):
    abort(401)
```

### Signature V2 (replay protection)

`X-CertForge-Signature` covers only the body, so a captured request can be
replayed. Prefer `X-CertForge-Signature-V2`: the same `sha256=` + lowercase-hex
HMAC-SHA256 with the same `signingSecret`, but computed over the
`X-CertForge-Timestamp` value, a literal `.`, then the exact body. Verify the
MAC, then reject the request when the timestamp is outside a freshness
window; 5 minutes either side is recommended.

```python
import hashlib, hmac, time

ts = request.headers.get("X-CertForge-Timestamp", "")
if not ts.isdigit() or abs(time.time() - int(ts)) > 300:   # 5 minute window
    abort(401)
expected = "sha256=" + hmac.new(signing_secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers.get("X-CertForge-Signature-V2", "")):
    abort(401)
```

`X-CertForge-Signature` (V1) is still sent unchanged for compatibility with
existing receivers; it carries no freshness guarantee, so migrate when you can.
Each delivery attempt by the job is signed afresh with a new timestamp. Only
the short in-call HTTP retries (bounded by the 45 s delivery timeout) reuse the
headers, so a 5-minute freshness window never rejects a legitimate retry.

## SMTP

An `smtp` channel emails `to` (1–20 addresses) through the server configured
in Settings → the `smtp` section (`docs/configuration.md#smtp-section`) — a
channel's own config only picks recipients and, optionally, a
`subjectPrefix` (default `[CertForge]`); the host, port, credentials,
security mode and timeout are shared by every `smtp` channel, not set per
channel. `Send` fails with "SMTP is not configured" when that section's
`host` is empty.

The message is `text/plain; charset=utf-8`, quoted-printable, one message
per event:

| Header | Value |
|---|---|
| `From` | The `smtp` section's `from` address |
| `To` | The channel's recipients, comma-separated |
| `Subject` | `<subjectPrefix> <summary>`, CR/LF-stripped, Q-encoded (RFC 2047) when it holds non-ASCII text |
| `Date`, `Message-ID`, `MIME-Version` | Standard RFC 5322 headers |

The body lists the event's summary, kind, severity, resource and time, one
`key: value` line per allowlisted `details` entry (the same allowlist the
Webhook payload's `details` uses), and — when CertForge's own base URL is
configured and the event belongs to an org — a link to that org's events
page.

`security: tls` dials straight into TLS (`ServerName` = the section's
`host`); `starttls` (the default) dials plaintext, then requires the server
to advertise `STARTTLS` — a server that does not is an error, never a
silent downgrade; `none` never upgrades. `AUTH PLAIN` runs only when the
section's `username` is set. Every dial goes through the same host-policy
machinery (`httpx.DialControl`) every HTTP notifier's dial uses, with
loopback always allowed — the SMTP relay is an operator-configured,
`settings:write`-gated global resource, not a per-channel URL a
lower-privileged actor could point anywhere, and is often local (a
mailhog/postfix on the same host) — only the cloud-metadata blocklist still
applies. The section's `timeoutSeconds` (1–60, default 10) becomes the
connection's own deadline. Every error SendMail returns has the password
redacted, so a bad password value can never surface through a delivery
failure, `notification_deliveries.last_error` or `POST
/api/v1/settings/smtp/test`'s response.

## Discord

A `discord` channel's `webhookUrl` (must be `https`) receives one embed per
event:

```json
{
  "username": "CertForge",
  "allowed_mentions": {"parse": []},
  "embeds": [{
    "title": "example.com expires in 7 days",
    "description": "notAfter: 2026-10-06T00:00:00Z",
    "color": 15844367,
    "timestamp": "2026-09-29T12:00:00Z",
    "fields": [
      {"name": "Kind", "value": "cert.expiring"},
      {"name": "Resource", "value": "example.com (certificate)"}
    ],
    "footer": {"text": "Acme"}
  }]
}
```

`title` is the event's `summary`, truncated to 256 characters. `description`
lists the same allowlisted `details` the Webhook payload sends, one
`key: value` line per entry (empty when there are none), truncated to 4096.
`color` is `0x3B82F6` for info, `0xF59E0B` for warning, `0xEF4444` for
critical. `footer` is left out entirely for a global event, which has no
org to name. `allowed_mentions.parse` is always an empty array, so an
event's `summary` or `details` can never ping a role or `@everyone`.

## ntfy

An `ntfy` channel POSTs the event's `summary` as plain text to
`<server>/<topic>` (`server` defaults to `https://ntfy.sh`), with:

| Header | Value |
|---|---|
| `Title` | `CertForge` or `CertForge — <org>`, with CR/LF and every non-printable character stripped, truncated to 200 characters |
| `Priority` | `3` for info, `4` for warning, `5` for critical |
| `X-Tags` | `<severity>,<kind with every . replaced by _>` — for example `warning,cert_expiring` |
| `Authorization` | `Bearer <token>`, when the channel has one |

## Home Assistant

A `homeassistant` channel POSTs the Webhook payload body (above) to
`<baseUrl>/api/webhook/<webhookId>` — a trailing slash on `baseUrl`, if any,
is stripped first, so the joined path never has a double slash. `webhookId`
must match `^[A-Za-z0-9_-]{1,128}$` (checked before it is ever placed in a
URL — it is otherwise concatenated straight into the request path) and is
stored encrypted like any other channel secret. Trigger a Home Assistant
automation on a `webhook` trigger with this ID, and read the JSON body's
`kind`, `severity`, `resource` and `summary` fields in its actions.

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
one. Settings → Notifications' **Allow loopback and link-local**
(`allowLoopbackUrls`, off by default) re-admits loopback and link-local
targets, for a home-lab setup reaching a channel or monitor on the same
host or network. RFC 1918 and other private-network addresses are always
allowed, regardless of this setting. Two addresses stay blocked either way:
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
