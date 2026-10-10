# Event reference

Every event kind CertForge raises, what triggers it, the details it carries, how duplicates are suppressed, and what a webhook receives. For setup, see [Alerts](../guide/alerts.md).

## Events

Each kind has a fixed severity and resource type. Events are listed by `GET /api/v1/orgs/{orgId}/events` (permission `alerts:read`), newest first. The list takes `kind` (repeatable), `severity` (a minimum), `since` and a `cursor` from the previous page's `nextCursor`. Each event carries one entry per channel it matched, with `status`, `attempts`, `lastError` and `deliveredAt`. Events older than 90 days are deleted.

| Kind | Severity | Resource | Fires when |
|---|---|---|---|
| `cert.issued` | info | certificate | A renewal or issuance commits a new version. Uploaded and imported versions do not fire. |
| `cert.renewal_failed` | warning | certificate | Consecutive failures reach the **Renewal failure threshold**. Then at most once per UTC day. |
| `cert.expiring` | warning | certificate | The current version expires within the **Expiry warning (days)** window. |
| `cert.expired` | critical | certificate | The current version has expired. |
| `deploy.failed` | warning | grant | A live grant's deployment is in state failed. |
| `deploy.drift` | warning | grant | An agent grant's installed files no longer match. Server grants have no drift. |
| `client.offline` | warning | client | An active client with a live grant was last seen longer ago than **Offline after (seconds)**. |
| `agent.cert_expiring` | warning | client | An active client's agent certificate expires within 14 days. |
| `client.pending_approval` | warning | client | An agent redeemed its token and waits for approval. |
| `monitor.mismatch` | critical | monitor | A monitor's endpoint serves an unexpected certificate. |
| `monitor.unreachable` | warning | monitor | Two checks in a row failed. |
| `monitor.expiring` | warning | monitor | The endpoint's certificate expires soon. |
| `monitor.recovered` | info | monitor | A monitor in a bad state returned to OK. |
| `backup.completed` | info | backup | A backup finished. |
| `backup.failed` | critical | backup | A backup failed. |
| `test` | info | channel | **Send test** on one channel. |

`cert.issued` and `cert.renewal_failed` fire as the issuance happens. Deployment, client and certificate-expiry kinds are found by a scan that runs hourly and at server start, up to 1000 candidates per kind per run. Monitor events come from the monitor checks and backup events from the backup job.

`backup.*` events belong to no org. A channel receives a global event only when **All orgs** is on. An org-scoped channel receives its own org's events only.

## Details

Only these `details` keys are ever sent. Anything else is dropped before delivery.

| Kind | Details keys |
|---|---|
| `cert.issued` | `serial`, `notAfter`, `names`, `caName` |
| `cert.renewal_failed` | `failures`, `step`, `problemType`, `status`, `class`, `nextAttemptAt` |
| `cert.expiring`, `cert.expired` | `commonName`, `notAfter` |
| `deploy.failed` | `target`, `lastError` |
| `deploy.drift` | `target` |
| `client.offline` | `lastSeen` |
| `agent.cert_expiring` | `notAfter` |
| `client.pending_approval` | `verifyCode`, `hostname`, `expiresAt` |
| `monitor.*` | `host`, `port`, `fp`, `issuer`, `notAfter`, `chainError`, `error` |
| `backup.completed` | `sizeBytes`, `file` |
| `backup.failed` | `error` |
| `test` | none |

A failed renewal never sends its raw cause. `class` is one of `acme`, `dns`, `caa`, `rate_limit`, `challenge`, `signer` or `internal`. `step` names the failed step. `problemType` and `status` appear only when the CA returned them. No URL or hostname is included.

## Dedupe

Each condition fires once. Raising an event whose dedupe key already exists does nothing and is not an error.

| Kind | Dedupe key |
|---|---|
| `cert.issued` | `cert.issued:<versionId>` |
| `cert.renewal_failed` | `cert.renewal_failed:<certId>:<UTC yyyy-mm-dd>` |
| `cert.expiring` | `cert.expiring:<versionId>` |
| `cert.expired` | `cert.expired:<versionId>` |
| `deploy.failed` | `deploy.failed:<grantId>:<versionId>` |
| `deploy.drift` | `deploy.drift:<grantId>:<versionId>` |
| `client.offline` | `client.offline:<clientId>:<last_seen unix>` |
| `agent.cert_expiring` | `agent.cert_expiring:<clientId>:<agent certificate serial>` |
| `client.pending_approval` | `client.pending_approval:<requestId>` |
| `monitor.<state>` | `monitor.<state>:<monitorId>:<fingerprint>:<state_changed_at unix>` |
| `backup.completed` | `backup.completed:<file>` |
| `backup.failed` | `backup.failed:<UTC yyyymmddhh>` |
| `test` | `test:<random uuid>` (never dedupes) |

A new version, a client coming back and going offline again, and a monitor entering the same state a second time are all new conditions.

## Delivery

Each matching, enabled channel gets its own delivery for each event. A delivery is retried up to 12 times with exponential backoff: 30 seconds, doubling each time, capped at 1 hour. That is about five hours before it is marked `failed`. Each attempt times out after 45 seconds. A failing channel never delays another channel.

HTTP channels never follow redirects, ignore proxy environment variables and cap the response at 64 KiB. Within one delivery attempt they make up to 3 tries on a connection error, a 5xx or a 429. TLS verification is never turned off. A channel's PEM only adds trusted roots.

## Webhook payload

Webhook and Home Assistant channels send the same JSON body. `org` is `null` for a global event.

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

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `CertForge/<version>` |
| `X-CertForge-Event` | The event `kind`. |
| `X-CertForge-Delivery` | The event `id`. |
| `X-CertForge-Signature` | `sha256=<hex HMAC of the body>`. Only with a signing secret. |
| `X-CertForge-Timestamp` | Unix seconds when the request was signed. Only with a signing secret. |
| `X-CertForge-Signature-V2` | `sha256=<hex HMAC of timestamp + "." + body>`. Only with a signing secret. |
| `Authorization` | The channel's **Authorization header**, sent as entered. |

Extra headers are added too: at most 20, names matching `^[A-Za-z0-9-]{1,64}$`, values up to 1024 characters. These names are refused: `Authorization`, `Cookie`, `Proxy-Authorization`, `Host`, `Content-Type`, anything starting `X-CertForge-`, and anything containing `token`, `key`, `secret` or `auth`.

## Signature

With a signing secret, verify every request. Prefer V2, which stops replays. `X-CertForge-Signature` covers only the body and carries no freshness. It is still sent for older receivers.

1. Read the raw request body. Do not re-serialize it.
2. For V2, compute HMAC-SHA256 over `X-CertForge-Timestamp`, a `.`, then the body, keyed by the secret. Prefix the lowercase hex with `sha256=`.
3. Compare with `X-CertForge-Signature-V2` in constant time.
4. Reject the request if the timestamp is more than 5 minutes from your clock.

```python
import hashlib, hmac, time

ts = request.headers.get("X-CertForge-Timestamp", "")
if not ts.isdigit() or abs(time.time() - int(ts)) > 300:
    abort(401)
expected = "sha256=" + hmac.new(signing_secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers.get("X-CertForge-Signature-V2", "")):
    abort(401)
```

```go
mac := hmac.New(sha256.New, []byte(signingSecret))
mac.Write(body) // the raw request body, unparsed
expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
if !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-CertForge-Signature"))) {
    http.Error(w, "bad signature", http.StatusUnauthorized)
    return
}
```

The Go sample checks the body-only V1 signature. Each attempt is signed afresh with a new timestamp, so a 5-minute window never rejects a legitimate retry.

## Other wire formats

| Channel | Format |
|---|---|
| Email | `text/plain`, quoted-printable. Subject is `<prefix> <summary>`. The body lists summary, kind, severity, resource, time and the allowed details. |
| Discord | One embed. `title` is the summary (256 characters at most). `description` lists the details. `color` is `0x3B82F6` for info, `0xF59E0B` for warning, `0xEF4444` for critical. `allowed_mentions.parse` is always empty. |
| ntfy | `POST <server>/<topic>` with the summary as the body. `Title` is `CertForge` or `CertForge — <org>`. `Priority` is 3, 4 or 5. `X-Tags` is `<severity>,<kind with . replaced by _>`. `Authorization: Bearer <token>` when set. |
| Home Assistant | The webhook payload, posted to `<baseUrl>/api/webhook/<webhookId>`. |
