# CertForge design specification

Status: approved 2026-09-24. This is the source of truth for scope, architecture, UI, and process. Phase plans live in `docs/superpowers/plans/` (local, not tracked), progress in `docs/PROGRESS.md`.


## Context

CertForge is a new, self-hosted certificate manager for a small team across several sites. It obtains certs from ACME CAs (Let's Encrypt and others) and from a private CA, stores them encrypted, and is the single place that decides which client gets which cert. Small agents on clients enrol with keypairs, connect over mTLS, and receive certs by push or pull. Humans log in via OIDC, machines via scoped API keys. Vault is optional for key wrapping, secret sync, and PKI signing. The outcome: never touch a cert by hand again, and see expiry and deployment state for everything at a glance.

The repo at `projects/home-assistant/certforge` is empty (git init, no commits). Sibling project `meter-hunt` already uses pgx/v5, coder/websocket and a WebSocket agent protocol package (`internal/agentwire`) whose framing and pipe tests can be reused.

## Decisions (agreed)

| Area | Choice |
|---|---|
| ACME engine | Go + `github.com/go-acme/lego/v4` in-process (all ~150 DNS providers, HTTP-01, TLS-ALPN-01, EAB, any CA) |
| Frontend | React + Vite + TS, embedded via `embed.FS`, single server container |
| Agent | Separate small Go binary and container, same repo |
| Transport | Agent dials out over HTTPS + mTLS, holds a WebSocket. Push = message down socket. Pull = REST over same mTLS. No inbound ports on clients. |
| Storage | Postgres. Private keys envelope-encrypted (per-row DEK, AES-256-GCM) wrapped by a KEK from env, file, or Vault Transit. |
| Vault | Optional: Transit (KEK), KV v2 (sync target), PKI (private CA signer). Works without Vault. |
| Private CA | Pluggable Signer: built-in Go x509 CA or Vault PKI |
| Scale | Small team, multi-site, orgs and sites, RBAC |
| Extras in scope | Hooks and deploy targets, notifications, drift and external monitoring, import and private CA (phased, see below) |

Stack details: sqlc + pgx/v5 + goose (type-safe SQL, no ORM). chi + oapi-codegen strict server (spec first, generated Go stubs and TS client cannot drift). river for jobs (durable, unique-per-cert, cron, in Postgres, no Redis). coder/websocket, coreos/go-oidc, sslmate go-pkcs12, keystore-go, hashicorp/vault/api. Web: TanStack Router/Query, shadcn/ui, openapi-typescript.

## Configuration principle: everything in the web UI

All configuration is done from the web UI and the API behind it. The only things read from the environment are what the server needs before it can reach the database and decrypt it:

| Env var | Why it cannot live in the DB |
|---|---|
| `CF_DATABASE_URL` | Needed to reach the DB at all |
| `CF_KEK` or `CF_KEK_FILE` or `CF_KEK_VAULT_TRANSIT_*` | Needed to decrypt anything in the DB |
| `CF_LISTEN_HTTP`, `CF_LISTEN_AGENT`, `CF_BASE_URL` | Needed before the first request arrives |

Everything else is a row in a `settings` table (typed key, JSON value, secrets encrypted) or a first-class entity with its own CRUD screens, and is editable live without a restart:

- **First-run setup wizard** in the UI: set local admin password, base URL check, choose KEK health, create first org. The wizard's KEK-health step reads `checks.kek` from `GET /readyz`; there is no separate setup-status field for it.
- **Settings → Authentication**: OIDC issuer, client id/secret, scopes, group claim, group-to-role mappings, session lifetime. Local admin login stays as break-glass.
- **Settings → Integrations**: Vault (address, auth method, AppRole or token, namespace), SMTP, Prometheus toggle.
- **Settings → Issuance defaults**: renewal policy, key type, preferred chain, ARI on/off, rate-limit thresholds, resolvers.
- **Settings → Agents**: agent CA view and rotation, agent-listener TLS cert (self-signed, upload, or pick a CertForge-issued cert), enrolment token TTL, heartbeat interval, hook allowlist defaults.
- **Settings → Backup**: trigger backup, key reminder, restore upload.
- **Entities with full CRUD screens**: orgs, sites, users and role bindings, API keys, CAs and ACME accounts, DNS credentials (form generated from provider schema), certificates, clients, grants and output specs, deploy targets, hooks, notification channels, external monitors, private CAs.

Every pluggable type (DNS provider, deploy target, notifier, signer) publishes a JSON Schema, and the UI renders its form from that schema. Adding a new provider or target never requires a UI change. `cfctl` and the API are alternatives to the UI, never prerequisites for it.

## Certificate configuration: domains, CA, verification, defaults

**Domains.** A certificate has one or more names: a common name plus any number of SANs, wildcards (`*.example.com`), and mixed zones (`example.com` and `other.net` in one cert). IP SANs are allowed where the CA supports them. The UI takes a free-form list with validation and shows which names are wildcards (DNS-01 only).

**Certificate authority.** Any ACME CA. The CA screen has presets (Let's Encrypt production and staging, ZeroSSL, Buypass, Google Trust Services, SSL.com) and a "custom" option that takes any directory URL, an optional trust bundle for private ACME servers (Pebble, step-ca, Vault ACME), and EAB key id and HMAC for CAs that require it. ACME accounts are created per CA per org with a contact email. Each cert picks its CA and account, or inherits the default.

**Verification (how you prove you own each name).** Each certificate carries an ordered list of verification rules matched by name pattern, first match wins, with a final catch-all inherited from defaults:

| Method | What the rule specifies | Who does the work |
|---|---|---|
| `dns-01` | a DNS provider credential (any of lego's ~150 providers), optional propagation timeout, resolvers, and delegated CNAME zone (`_acme-challenge` alias) | server, in-process via lego |
| `http-01` | webroot path on server, or an agent to serve the token | server standalone, or agent via WebSocket `challenge_present` |
| `tls-alpn-01` | an agent that owns port 443 for that name | agent |
| `manual-dns` | nothing; the UI shows the TXT records to add and waits for "I've added them" | operator |

Example: `*.example.com` → dns-01 Cloudflare credential; `other.net` → dns-01 Route53 credential; `lab.local` → manual. A routing ChallengeProvider dispatches lego's Present/CleanUp per domain to the matching credential, so one cert can span several DNS providers. v1 constraint: one challenge method per cert (DNS credentials may differ per name); mixing dns-01 and http-01 in one cert is Phase 4, since lego picks the solver per authorization and needs a wrapper to honour per-name rules.

**Defaults and overrides.** Every issuance field exists at three levels: global defaults (Settings → Issuance defaults), org defaults, and the certificate. A null at a lower level inherits from the level above. The UI shows the effective value and an "inherited from global/org" badge, with a "override" toggle per field. Fields covered: CA, account, key type, renewal policy (days or percent, ARI), preferred chain, reuse key, must-staple, verification rules (catch-all), propagation timeout, resolvers, pre/post hooks, notification channels, deploy targets. Changing a default takes effect at the next renewal of every cert that inherits it.

Model additions: `Certificate.verification_rules jsonb` (`[{match, method, dns_cred_id?, agent_client_id?, propagation_s?, resolvers?}]`), nullable override columns on `Certificate`, and an `IssuanceDefaults` row per scope (global, org) with the same columns.

## Repo layout

```
certforge/
├── api/openapi.yaml            # source of truth → Go stubs + TS client
├── cmd/certforge/              # server: serve | migrate | backup | restore | bootstrap-admin
├── cmd/certforge-agent/        # agent: enroll | run | pull | status
├── cmd/cfctl/                  # operator CLI over REST
├── internal/
│   ├── config/  db/  crypto/   # config; pool+migrations+sqlc; envelope encryption + KeyWrapper (env, file, vault-transit)
│   ├── authn/  authz/  audit/  # OIDC/sessions/API keys/mTLS principal; roles + Can(); append-only events
│   ├── api/                    # handlers, middleware, problem+json
│   ├── issuance/               # scheduler, river workers, renew policy, backoff, rate ledger, CAA, ARI
│   ├── signer/{acme,localca,vaultpki}/
│   ├── challenge/              # lego adapter, generated provider schemas, agent-delegated http/alpn
│   ├── certstore/  importer/  render/   # versions + upload; acme.sh/certbot import; pem/der/p12/jks/bundle
│   ├── agentca/  agenthub/  agentproto/  agent/   # client CA + enrollment; WS registry + dispatch; wire msgs; agent runtime
│   ├── deploy/targets/*  notify/channels/*  monitor/  vault/  metrics/
│   └── webui/                  # embed.FS(web/dist) + SPA fallback
├── web/                        # React + Vite + TS
├── tools/gen-lego-schemas/     # go:generate: lego provider .toml → JSON Schema
├── deploy/                     # Dockerfile.server, Dockerfile.agent, compose.yaml, compose.test.yaml
├── test/e2e/                   # compose-driven Go e2e + Playwright smoke
└── docs/superpowers/{specs,plans}/
```

## Domain model (🔒 = envelope-encrypted, `kek_id` stored per row)

| Entity | Key fields |
|---|---|
| Org / Site | id, slug, name / id, org_id, name |
| User | oidc_issuer, oidc_sub, email, disabled, last_login |
| RoleBinding | subject_type (user, oidc_group, apikey), subject, role, org_id?, site_id? |
| APIKey | prefix, sha256(secret), scopes[], org_id?, expires_at, last_used_at |
| CA | type (acme, localca, vaultpki), directory_url, staging, eab_kid, eab_hmac🔒, trust_bundle, resolvers[] |
| ACMEAccount | ca_id, org_id, email, account_key🔒, reg_uri, status |
| DNSProviderCredential | org_id, provider_code, name, public_cfg, secret_cfg🔒 |
| IssuanceDefaults | scope (global, org), org_id?, ca_id, account_id, key_type, renew_policy, preferred_chain, reuse_key, must_staple, verification_rules, propagation_s, resolvers[], hook_ids[], channel_ids[] |
| Certificate | org_id, name, common_name, sans[], verification_rules jsonb, plus nullable overrides of every IssuanceDefaults column (null = inherit), status, current_version_id, next_renew_at, failure_count, last_error |
| CertificateVersion | cert_id, serial, not_before, not_after, sha256_fp, leaf_der, chain_der[], private_key🔒, source (issued, imported, uploaded), ari_window, revoked_at |
| IssuanceAttempt | cert_id, started, finished, outcome, acme_error_type, retry_after, log |
| Client | org_id, site_id, name, status (pending, active, revoked), agent_cert_serial, agent_cert_not_after, hostname, agent_version, capabilities, last_seen |
| EnrollmentToken | client_id, sha256(token), expires_at, used_at |
| ClientCertGrant | client_id, cert_id, delivery (push, pull), output_spec_id, deploy_target_id?, auto_remediate |
| OutputSpec | files[{path, format, parts[], owner, group, mode}], extra_cert_ids[], password🔒 |
| DeployTarget | org_id, type, runs_on (server, agent), config, secrets🔒 |
| Hook | scope (cert, grant), phase (pre/post issue/deploy), runs_on, argv[], timeout |
| Deployment | grant_id, version_id, state (pending, ok, failed, drift), installed_fp, reported_at |
| NotificationChannel | org_id, type, config, secrets🔒, event_filter[] |
| ExternalMonitor | org_id, host, port, sni, interval, last_fp, last_not_after, last_error |
| AuditEvent | ts, actor_type, actor_id, action, resource, org_id, ip, details jsonb, prev_hash |
| AgentCA / LocalCA | cert, key🔒, active, not_after (multiple rows so rotation works) |
| KEK | id, provider, key_ref, active |

## Key flows

**Issuance and renewal**
1. River periodic job (5 min) selects certs with `next_renew_at <= now()`, enqueues one unique `issue{cert_id}` job each.
2. Pre-checks: CAA lookup per SAN, local rate-limit ledger (per registered domain, duplicates, new orders).
3. Load or register ACME account (EAB if needed). `Signer.Issue` via lego with the ChallengeProvider and configured key type.
4. Encrypt key, insert CertificateVersion. `next_renew_at` = ARI window if present, else `not_after` minus N days or a percentage of lifetime.
5. Emit `cert.issued`: notifiers, server-side deploy targets, Vault KV sync, `sync` nudge to online agents with a grant.
6. Failure: record attempt, back off `min(5m·2^n, 24h)` with ±20% jitter, honour `Retry-After` on rateLimited. Notify on 3rd failure or within 7 days of expiry. Daily ARI poll may pull renewal earlier.

**Agent enrolment** (server runs an internal ECDSA P-256 CA for agent identity)
1. Operator creates a Client. Server returns one-time token `cf1.<server_url>.<agent-ca-sha256>.<secret>` (hashed at rest, 24h TTL).
2. Agent generates ECDSA keypair (`/data/agent.key`, 0600) and CSR.
3. `POST /agent/v1/enroll {token, csr, facts}` over TLS, server pinned by the CA fingerprint in the token (no trust-on-first-use).
4. Server consumes token atomically, signs a 90-day clientAuth cert with URI SAN `urn:certforge:client:<uuid>`, returns cert and trust bundle.
5. Agent dials `wss://server:8443/agent/v1/ws` with mTLS. Server maps SAN to Client, checks active status and serial.
6. At 2/3 lifetime, agent calls `POST /agent/v1/renew` with a fresh CSR. Revoking a client closes its socket.

**Push and pull (level-triggered)**
1. Each client has a `desired_revision`. Any grant or version change bumps it.
2. Push: server sends `sync{revision}`. Pull: agent schedule or `certforge-agent pull`. Both then `GET /agent/v1/assignments`.
3. Per changed grant: `GET /agent/v1/grants/{id}/bundle`. Agent writes temp file, fsync, rename, apply owner/mode.
4. Agent runs post-deploy hooks and agent-side deploy targets, sends `deploy_result{grant, fp, hook_status}`.
5. Other messages: `hello`, `heartbeat`, `challenge_present/cleanup`, `trust_bundle_update`, `ping`. No request/response on the socket; missed messages are harmless because the agent reconciles to the latest revision.

**Drift**: heartbeat every 60s carries `installed[]{grant_id, path, sha256_fp, mtime}`. Mismatch or missing file sets Deployment=drift, audits, notifies. `auto_remediate` bumps revision. External monitors reuse the same comparison via TLS scan.

**Vault**: Transit = KeyWrapper with a rewrap job after key rotation. KV v2 = server-side DeployTarget `vault-kv` with path template. PKI = Signer posting CSRs to `pki/sign/<role>`. Auth via token, AppRole, or Kubernetes with lease renewal. All behind interfaces.

**Formats**: canonical storage as leaf DER, chain DER, PKCS#8 key. Renderers are pure `(material, opts) → []File`: PEM parts (cert, chain, fullchain, key, combined), DER, PKCS#12 (Modern2023 default, legacy option), JKS. Bundles are ordered part lists that may pull from several certs.

**Traefik on clients** (agent-side DeployTarget `traefik`, Phase 3 with the agent; it is the reference deploy target)
- Traefik's file provider watches a directory (`providers.file.directory=/etc/traefik/dynamic`, `watch=true`) and hot-reloads TLS certs without a restart. CertForge does not use Traefik's built-in ACME at all; the agent is the source of certs.
- The agent container and the Traefik container share one volume mounted at that directory. Per grant the agent writes three files atomically (temp, fsync, rename): `certs/<name>/fullchain.pem`, `certs/<name>/privkey.pem`, and `certforge-<name>.yml` containing `tls.certificates[]` with `certFile`/`keyFile` paths as seen by Traefik, plus optional `tls.stores.default.defaultCertificate` when the grant is marked default. No hook, no reload command, no Docker socket.
- Renewal: the agent overwrites the same paths and touches the yml file so Traefik's watcher fires. Revoking a grant removes the yml file first, then the cert files.
- Config surface on the grant: `traefik_dir` (agent path), `traefik_path_prefix` (path as Traefik sees it, default same), `default_cert` bool, `stores[]` (Traefik TLS store names, default `default`).
- Traefik on Kubernetes uses the K8s Secret target (Phase 7); IngressRoute or TLSStore references the secret by name.
- HTTP-01 through Traefik (Phase 4): when a site has no DNS provider, the agent can serve `/.well-known/acme-challenge/` on a local port and the traefik target emits a router rule for that path pointing at the agent's service. Traefik forwards the challenge, the agent answers with the token the server sent over the WebSocket.

## Web UI design (Opus-designed; implementation must follow this, not improvise)

**Navigation.** Sidebar with 8 items in three groups. Org switcher at the top of the sidebar, user menu and theme toggle at the bottom.

| Group | Item | Sub-pages (tabs) | Why top-level |
|---|---|---|---|
| Operate | Overview | – | See what is expiring, failing, drifted |
| | Certificates | – | The core object |
| | Clients | – | The second core object |
| Configure | Issuers | CAs, ACME accounts, DNS credentials, Private CAs | How a cert is obtained |
| | Delivery | Deploy targets, File layouts (output specs), Hooks | Where a cert goes |
| | Alerts | Notification channels, External monitors | What tells you about a problem |
| Govern | Audit log | – | First stop when diagnosing |
| | Settings | General (base URL, orgs, sites), Access (users, bindings, API keys), Authentication (OIDC), Issuance defaults, Agents, Integrations (Vault, SMTP, Prometheus), Backups | Set up once |

Scope: global = CAs, private CAs, Settings, users, KEK (shown with a "Shared" badge in org views, admin-only edit). Org-scoped = everything else. Site is a filter (`?site=`), not a scope. Org switcher has "All orgs" for admins (read-only across Overview, Certificates, Clients, Audit).

URLs: `/login`, `/setup`, `/o/:org/{overview|certificates|clients|audit}`, `/o/:org/certificates/new`, `/o/:org/certificates/:id/:tab`, `/o/:org/issuers/{cas|accounts|dns|private-cas}/:id?`, `/o/:org/delivery/{targets|layouts|hooks}`, `/o/:org/alerts/{channels|monitors}`, `/settings/:section`. Filters and sort live in typed search params (TanStack Router `validateSearch` + zod) so any view is shareable by URL.

**Screen inventory**

| Route | Purpose | Key content | Primary action |
|---|---|---|---|
| `/login` | Sign in | OIDC button; local admin behind "Break-glass login" | Sign in |
| `/setup` | First run | Admin password → base URL check → KEK canary → first org → optional first CA | Finish setup |
| `overview` | Triage | Health strip, attention queue, expiry horizon, upcoming renewals, recent activity | Open top attention item |
| `certificates` | Inventory | Name, names, status, validity bar, CA, next renew, grants | New certificate |
| `certificates/new` | Issue | 4-step wizard | Issue certificate |
| `certificates/:id` | Diagnose, manage | Tabs: Overview, Versions, Attempts, Deployments, Settings | Renew now |
| `clients` | Fleet | Connection dot, site, agent version, grants, drift count, last seen | Enrol client |
| `clients/new` | Enrol | Name, site → one-time token + `docker run` and compose snippets → live "waiting for agent" | Create token |
| `clients/:id` | Per-host state | Tabs: Certificates (grants), Hooks, Activity, Settings | Grant certificate |
| `issuers/cas` | ACME + private endpoints | Preset cards (LE prod/staging, ZeroSSL, Buypass, GTS, SSL.com), Custom (directory URL, trust bundle, EAB) | Add CA |
| `issuers/accounts` | ACME accounts | CA, email, status, registration URI | Register account |
| `issuers/dns` | DNS credentials | Provider, name, "used by N certs" | Add credential |
| `issuers/private-cas` | Signers | Built-in or Vault PKI, schema form, expiry, rotation | Create private CA |
| `delivery/targets` | Deploy targets | Type, runs on, schema form, Probe | Add target |
| `delivery/layouts` | Output specs | File rows (path, format, parts, owner, group, mode), extra certs, password | New layout |
| `delivery/hooks` | Hooks | Scope, phase, runs on, argv editor, timeout, allowlist warning | New hook |
| `alerts/channels` | Notifiers | Type, event filter chips, Send test | Add channel |
| `alerts/monitors` | TLS scans | host:port, SNI, interval, last fingerprint, match state | Add monitor |
| `audit` | Evidence | Time, actor, action, resource, IP, JSON diff, filters, hash-chain status | Export CSV |
| `settings/*` | Configuration | See nav table; every section has Save and, where relevant, "Test connection" or "Test login" | Save |

**Dashboard.** Top to bottom: (1) health strip, shown only when something is wrong (scheduler stalled, KEK canary failed, Vault unreachable, listener cert under 14 days, no backup in 7 days); (2) needs-attention queue sorted by severity then time to impact, each row with cause, object, one inline fix (expired, issuance failed, waiting on manual-dns, renewal overdue, deploy failed, drift, client offline with grants, agent cert expiring); (3) 90-day expiry horizon, one tick per cert coloured by status, renewal window shaded, brushing filters the list; (4) upcoming renewals (7 days) beside recent activity (last 20). Count tiles are filters only. No vanity metrics.

**Certificate create wizard.** Persistent summary rail on the right. Steps 3 and 4 skippable, so the fast path is paste names → pick credential → Issue.
1. Names: multi-line paste box splitting on commas, spaces, newlines. Each name becomes a chip (wildcard = "DNS only", IP chip, invalid = red inline). First name is CN, drag to change. Grouped by registered domain.
2. Verification: method selector on top (v1 one method per cert). Ordered rule table (drag to reorder) with match pattern, credential, Advanced (propagation, resolvers, CNAME alias zone). One rule per zone pre-filled using the credential last used for that zone. Coverage panel lists every name with its matching rule or "Catch-all: inherited from Org".
3. Options: all inheritable fields.
4. Review: effective config, then Issue. Lands on the detail page with the live attempt open.

`InheritableField` component: label, effective value, badge `Global` or `Org` (hover shows chain), Override switch turns it into an editor, "Reset to inherited" sends null. Reused in Settings → Issuance defaults.

DNS provider picker: cmdk dialog searching name, code, aliases. Sections: credentials in this org, recently used, common (Cloudflare, Route 53, Azure, GCP, DigitalOcean, OVH, Hetzner, Gandi, Porkbun), all A–Z. Picking a provider with no credential opens a side sheet with the schema form so the wizard is never lost.

manual-dns: amber action card on the detail page with a TXT table (name, type, value, TTL, copy buttons, "copy all as zone lines"), timeout countdown, "I've added them" button. Same card pinned at the top of the dashboard queue.

**Certificate detail.** Header: name, status chip, large validity bar with "renews in N d" marker, CA, account. Actions: Renew now, Download, Duplicate; overflow: Revoke (type name to confirm, reason code), Delete. Tabs: Overview (names, coverage, effective config, linked targets and channels); Versions (serial, validity, SHA-256, source, revoked, compare chains, download per version); Attempts (outcome, duration, ACME error type, expandable step timeline and log, next retry and backoff reason); Deployments (grant × client matrix with delivery, layout, target, state, installed vs current fingerprint, Redeploy); Settings (wizard steps as editable sections). Download sheet: version combobox, format segmented control (PEM, DER, PKCS#12 Modern2023 or legacy, JKS), part chips (cert, chain, fullchain, key, combined), generated password with copy for P12/JKS, key notice "recorded in audit log", key disabled without `keys:export`.

**Client detail.** Header: connection dot and label (Online, Offline since, Never connected), hostname, site, agent version with "Update available" badge, capabilities, agent cert expiry. Tabs: Certificates (grants editor: cert, delivery, layout, target, auto-remediate, state; drift row expands to expected vs installed with Redeploy; "Grant certificate" picks several certs then a layout and target); Hooks (run history with phase, argv, exit code, duration, stdout/stderr); Activity (audit filtered to client); Settings (name, site, Re-enrol, Revoke with type-to-confirm).

**Controls: no checkboxes, no radio buttons.**
- Booleans are toggle switches with the label on the left and state text on the right (On/Off, or the specific meaning such as "Rotate key on renewal").
- Small enums (2 to 5 options: delivery push/pull, key type, renewal mode days/percent, theme) are segmented controls.
- Sets (download parts, notification event filters, capabilities, sites, hooks on a cert) are selectable chips in a wrap row; selected chips fill with the primary token and show a check glyph inside the chip.
- Lookups (CA, account, credential, client, cert) are comboboxes with search, and multi-lookups render selected items as removable chips.
- Row selection in tables uses row highlight on click, shift-click for ranges, and a floating bulk-action bar at the bottom; there is no leading checkbox column.
- The `SchemaForm` theme maps JSON Schema `boolean` to a switch, `enum` with 5 or fewer values to a segmented control, larger enums to a combobox, and `array` of `enum` to chips, so generated provider and target forms follow the same rules.
- Native `<input type="checkbox">` and `<input type="radio">` are lint-blocked in `web/` (ESLint rule) so the rule holds as the UI grows.

**Help and explanation: tooltips, never paragraphs.**
- No inline explanatory text on any screen. Every field, column header, status chip, and badge that needs explaining gets an info icon with a tooltip of at most two short sentences (Radix Tooltip via shadcn, hover and focus, 300 ms delay, keyboard reachable).
- Field labels are short nouns. Placeholders show an example value, not instructions.
- Tooltip text comes from a single `web/src/lib/help.ts` map keyed by field id, so copy is reviewed in one place and translated later. Schema-driven forms take tooltip text from the JSON Schema `description`, so provider and target forms are covered automatically.
- Longer help (for example, how to delegate `_acme-challenge` via CNAME) goes behind a "Learn more" link inside the tooltip that opens the docs in a new tab. It never expands in-page.
- Empty states are one sentence plus one button. Error explanations in the attempt viewer are one line plus a fix link; the raw log is collapsed.
- Wizard steps have no intro text. The summary rail and the coverage panel do the explaining by showing state.
- Destructive dialogs state the consequence in one sentence, then the confirm input.

**Themes: dark and light.**
- Both themes are first-class, designed together, not dark derived from light. Every token in the table below has a light and a dark value in `styles/tokens.css` under `:root` and `[data-theme="dark"]`, and `prefers-color-scheme` picks the default.
- Toggle in the user menu with three options: System, Light, Dark. The choice persists per browser in localStorage and applies before first paint (inline script in `index.html`) to avoid a flash.
- Status colours get separate dark values with the same hue so a chip reads the same in both themes. The validity bar, expiry horizon, and log viewer are checked in both themes as part of the Playwright smoke test (screenshot in each).
- shadcn components are themed through the same tokens, so no component carries its own colours.
- Surfaces form a four-step elevation ladder, darkest to lightest in dark and tinted greys in light: sidebar (`bg-sidebar`, with a right border) < page canvas (`bg-surface`) < card (`bg-panel` plus a border) < overlay (`bg-raised`: dialogs, sheets, popovers, menus, the palette). Shared components apply it: `Card`, a titled `FormSection`, `SchemaSection` and every table (`ui/table`, a framed container with a `bg-subtle` header) sit on the canvas as framed cards; a table or `FormSection` inside a `Card` drops its own frame. Nothing sits loose on the canvas, there is no borderless card variant, and no in-page shadow.

**Cross-cutting patterns.**
- Lists: TanStack Table, compact density, URL-synced filters in a labelled filter toolbar (`FilterToolbar`/`FilterField`, with Clear filters and saved views) under the tab strip, folding into a Filters popover with removable chips below `md`, saved views in localStorage and shareable by URL, bulk actions (renew, grant, delete) via click-to-select rows and a floating action bar, status chips always icon plus word.
- Secrets: schema field `secret: true` renders "Stored" plus Replace; untouched sends the unchanged sentinel. New secrets shown once in a copy-then-acknowledge dialog.
- Destructive: revoke and anything that orphans dependents require typing the name. Deleting a CA, credential, or layout lists dependents and is blocked while any exist.
- Empty states give the next concrete step with a button.
- Attempt log viewer: step timeline (CAA → rate ledger → account → order → per-name challenge → finalize → store), failing step expanded, ACME error type mapped to a plain explanation and fix link, raw log collapsible with search and copy.
- Live status: TanStack Query polling. 2 s during an attempt or enrolment, 30 s on lists, paused when tab hidden. No SSE in v1.
- Command palette (cmdk, Ctrl/Cmd-K): jump to any cert by any SAN, client, or settings page; actions New certificate, Enrol client, Renew x. Shortcuts `g o`, `g c`, `g l`, `n c`.
- Breakpoints: ≥1280 full sidebar, 768–1279 icon rail, <768 drawer nav and card lists (mobile targets triage, not configuration).
**Visual direction.** Type: Atkinson Hyperlegible Next for UI, Atkinson Hyperlegible Mono for machine values only (FQDNs, fingerprints, paths, logs), chosen for 0/O and 1/l/I distinction. Scale 13/14/16/20/28, sentence case, no all-caps labels. Tokens (light / dark): ink `#1D2533` / `#E8EBF1`, surface `#F2F4F7` / `#0D1015`, panel `#FFFFFF` / `#171C25`, sidebar `#E8ECF1` / `#08090D`, raised `#FFFFFF` / `#1E2430`, border `#C5CCD8` / `#343E50`, primary `#2848B8` / `#7C97F0`, valid `#2E7D57` / `#5BC08A`, expiring `#B7791F` / `#E0A83F`, expired `#7F1D2D` / `#D9647A` filled, failed `#D0342C` / `#F0665E` outlined (an event, not a state), drift `#6B4BC8` / `#A48CF2`, pending `#4A6A8C` / `#8FAACB` animated dash. Contrast checked to WCAG AA in both themes. Density: 36 px rows, 6 px radius on controls, none on rows, no drop shadows in-page. Signature element: the **validity bar**, used everywhere a cert appears: thin track from not_before to not_after, shaded renewal window, "now" notch, ghost segment for the next version once issued.

**Folder structure**
```
web/src/
  api/         schema.d.ts (openapi-typescript), client.ts (openapi-fetch), queries/*.ts
  routes/      TanStack file routes: __root, login, setup, o.$org/{overview,certificates,clients,issuers,delivery,alerts,audit}, settings/$section
  features/    certificates/ clients/ issuers/ delivery/ alerts/ audit/ settings/ setup/ (components, hooks, columns.ts each)
  forms/       SchemaForm (RJSF + shadcn theme), widgets/{SecretField,ArgvField,DurationField,PathModeField}, InheritableField, VerificationRulesEditor, ProviderPicker
  components/  ValidityBar, StatusChip, DataTable, ConfirmDestructive, EmptyState, AttemptLogViewer, CopyField, OrgSwitcher, CommandPalette, ui/ (shadcn)
  lib/         status.ts, time.ts, permissions.ts (Can() mirror), polling.ts
  styles/      tokens.css (light/dark), fonts
```

**UI phase mapping**

| Phase | Screens |
|---|---|
| 1 | Login (local admin), first-run wizard, Overview (cert tiles), Certificates list/detail/wizard (dns-01, manual-dns), PEM download, CAs, accounts, DNS credentials, Settings: General, Issuance defaults (Global + single org), Backup (KEK status). Org switcher hidden. |
| 2 | Org/site switcher, All orgs, Settings: Access, Authentication, Audit log, orgs and sites CRUD |
| 3 | Clients list/detail/enrol, grants editor, Deployments tab, File layouts, Deploy targets (Traefik), Hooks, drift and offline queue items, Settings → Agents |
| 4 | DER/P12/JKS/bundles in Download, http-01 and tls-alpn-01 and per-rule method, Import and Upload screens, CAA and rate-ledger in attempt log, ARI field |
| 5 | Private CAs, Settings → Integrations (Vault), KEK rotation and rewrap progress |
| 6 | Alerts channels and monitors, SMTP and Prometheus, full Backup and restore |
| 7 | No new screens; targets arrive as schemas |

## Auth and authorization

| Principal | Mechanism |
|---|---|
| Human | OIDC auth-code + PKCE, server-side session in Postgres, HttpOnly SameSite=Lax cookie + CSRF token. Group claim maps to RoleBindings. Local bootstrap admin for break-glass. |
| Machine | `Authorization: Bearer cf_<prefix>_<secret>`, scopes, optional org scope, expiry. |
| Agent | mTLS on a separate listener (:8443) serving only `/agent/v1/*`. |

Roles: admin (everything incl. CAs, KEKs, OIDC mappings), org-admin (full within org), operator (certs, creds, clients, grants, targets, hooks, issue/renew), viewer (read-only, no secrets), auditor (viewer + audit log). `keys:export` is a separate permission held only by admin by default; every key read is audited. `dnscreds:reveal` is likewise admin-only and audited. API key scopes: `certs:read`, `certs:write`, `certs:issue`, `keys:export`, `dnscreds:reveal`, `clients:write`, `admin`, intersected with the creator's role.

## Interfaces to define early

```go
type Signer interface { Kind() string; Issue(ctx, IssueRequest) (*Issued, error); Revoke(ctx, *x509.Certificate, int) error; RenewalInfo(ctx, *x509.Certificate) (*Window, error) }
type ChallengeProvider interface { Type() ChallengeType; Present(ctx, domain, token, keyAuth string) error; CleanUp(ctx, domain, token, keyAuth string) error; Timeout() (time.Duration, time.Duration) }
type DeployTarget interface { Type() string; Schema() jsonschema.Schema; Deploy(ctx, Rendered, Config) (Result, error); Probe(ctx, Config) (fp string, err error) }
type Notifier interface { Type() string; Schema() jsonschema.Schema; Send(ctx, Event, Config) error }
type KeyWrapper interface { ID() string; Wrap(ctx, dek []byte) ([]byte, error); Unwrap(ctx, []byte) ([]byte, error) }
type SecretsSink interface { Put(ctx, path string, data map[string]any) error }
type Renderer interface { Format() string; Render(Material, OutputOpts) ([]File, error) }
type Importer interface { Detect(fs.FS) bool; Import(ctx, fs.FS) ([]ImportedCert, error) }
```

Every implementation registers a type code and JSON Schema. The UI builds forms from `GET /api/v1/meta/schemas`; fields marked `secret: true` are write-only, except that a global admin can reveal one stored DNS credential secret field on demand (`dnscreds:reveal`, audited).

## Phases (each gets its own spec and implementation plan)

| # | Spec | Delivers | Depends |
|---|---|---|---|
| 1 | Core issuance slice | Scaffold, bootstrap env config, `settings` table + Settings UI framework, first-run wizard, migrations, sqlc, envelope encryption (env/file KEK), local admin login, CA presets + custom directory URL + EAB + staging, ACME accounts, DNS credentials for all lego providers (generated schemas), global and org issuance defaults with per-cert overrides, Certificate CRUD with multi-SAN and wildcard, per-name DNS-01 verification rules (routing provider), manual-dns, scheduler with backoff, cert list/detail/expiry UI, PEM download, `/healthz` `/readyz`, server image, compose with Pebble | – |
| 2 | Identity and tenancy | OIDC configured in Settings UI, sessions, orgs/sites, RBAC and bindings, scoped API keys, audit log, OpenAPI completeness + CI drift check | 1 |
| 3 | Agent | Agent CA, enrollment tokens, mTLS listener, WS hub, grants, push and pull, PEM output with owner/mode, Traefik file-provider target (reference agent-side DeployTarget), agent hooks (local allowlist), heartbeat, drift, agent image, clients UI | 2 |
| 4 | Issuance breadth and formats | DER/P12/JKS/bundles, HTTP-01 (server or agent webroot/standalone), TLS-ALPN-01 via agent, mixed challenge methods within one cert, CAA, rate ledger, ARI, acme.sh/certbot import, manual upload | 3 |
| 5 | Vault and private CA | vault-transit KeyWrapper, KEK rotation + rewrap, vault-kv target, localca signer, vaultpki signer | 2 |
| 6 | Ops | Notifiers (webhook, SMTP, Discord, ntfy, HA), Prometheus metrics, external monitors, backup/restore (pg_dump + KEK manifest), `cfctl` | 2 |
| 7 | Deploy targets | Docker secrets, K8s Secret, Home Assistant, UniFi, Proxmox, TrueNAS, OPNsense. Each runs on server or agent. | 3, 4 |

Phase 7 delivered the target framework; vendor targets (Docker secrets, Kubernetes Secret, Proxmox VE, TrueNAS, OPNsense, UniFi, Home Assistant) on demand.

## Risks

- **lego providers read credentials from env vars.** Build providers under a global mutex (set env, construct, restore), subprocess fallback. Generate schemas from lego's per-provider `.toml`; pin the lego version.
- **TLS-terminating proxies strip client certs.** Agent port needs TLS passthrough. Never trust forwarded client-cert headers by default.
- **Half-open WebSockets behind CGNAT.** Ping 25s with read deadline, jittered reconnect, new session evicts old. Single replica in v1; multi-replica needs LISTEN/NOTIFY fan-out.
- **KEK loss = all keys lost.** `kek_id` per row, rewrap job, canary decrypt at startup, backups carry a dismissible reminder to keep a copy of the key.
- **Agent CA and listener cert rotation.** Multi-CA trust bundle, push `trust_bundle_update`, re-issue agent certs, then retire old CA.
- **Server compromise = code exec on every agent.** Hooks off by default, local allowlist `CF_HOOK_ALLOW`, argv only, never a shell.
- **Shorter cert lifetimes** (45-day, 6-day). Default to percentage renewal + ARI, not a hard 30 days.
- **~150 provider forms with secrets.** Write-only secret fields with "unchanged" sentinel, searchable picker, per-provider propagation/resolver overrides.

## Verification (Phase 1)

- `compose.test.yaml`: postgres, `letsencrypt/pebble` (`PEBBLE_VA_NOSLEEP=1`, `-dnsserver challtestsrv:8053`), `pebble-challtestsrv`, certforge.
- Fake DNS ChallengeProvider (`e2e` build tag) calling challtestsrv `/set-txt` and `/clear-txt`. CA `resolvers` = challtestsrv, `trust_bundle` = Pebble minica.
- Unit: envelope encryption round-trips, renderers (golden files), backoff and next-renew with fake clock, schema generation.
- Integration: testcontainers-go Postgres for migrations and sqlc; river scheduler with fake Signer.
- E2E (Go, `-tags e2e`): create CA at `https://pebble:14000/dir`, credential, cert for `example.test` + `*.example.test`; poll to active; verify chain against Pebble `:15000/intermediates/0`, SANs, key type; force renewal, assert second version; break credential, assert failure recorded and backoff scheduled.
- Playwright smoke: log in, see cert with expiry, open details, download PEM.
- Phase 3 adds an agent service: token → client active; grant → file appears with matching fingerprint; tamper → drift; server restart → agent reconnects and reconciles.
- CI: `go test -race`, golangci-lint, vitest, `make generate && git diff --exit-code`.

## Process: commits, progress tracking, documentation

**Commits.** One commit per completed task in the implementation plan, never a batch at the end. Author `metril <1517921+metril@users.noreply.github.com>`. Conventional commit prefixes (`feat`, `fix`, `docs`, `test`, `chore`, `refactor`) with a scope (`feat(issuance): ...`, `feat(web): ...`, `feat(agent): ...`). Each commit passes lint and tests before it is made. The spec and each phase plan are committed before implementation starts. Docs and CHANGELOG changes go in the same commit as the code they describe.

**Progress tracking.** `docs/PROGRESS.md` is the single status file, updated in every commit that completes a task:
- A phase table: phase, status (planned, in progress, done), spec link, plan link, start and finish dates.
- Under the active phase, the task list from its plan with status per task and the commit hash that closed it.
- A "Decisions made during implementation" list with one line per deviation from the spec and why.
- A "Known gaps" list so nothing is silently dropped.
`CHANGELOG.md` at the repo root follows Keep a Changelog, with an Unreleased section that each feature commit appends to.

**Documentation set** (all markdown in `docs/`, written as the feature lands, not after):

| File | Audience | Content |
|---|---|---|
| `README.md` | Anyone landing on the repo | What CertForge is, 5-minute quick start with compose, screenshots, links to docs |
| `docs/architecture.md` | Developers | Components, data flow diagrams (Mermaid), the interfaces, the envelope encryption scheme, the agent protocol |
| `docs/configuration.md` | Operators | Bootstrap env vars, first-run wizard, every Settings section with each field explained |
| `docs/certificates.md` | Operators | Names, CAs and presets, EAB, verification methods and rules, defaults and overrides, renewal policy, ARI |
| `docs/dns-providers.md` | Operators | Generated from lego schemas: one section per provider with required fields and notes |
| `docs/agent.md` | Operators | Enrolment, docker run and compose examples, grants, file layouts, hooks and allowlist, Traefik integration, drift, troubleshooting |
| `docs/deploy-targets.md` | Operators | One section per target with its fields and an example |
| `docs/notifications.md` | Operators | Channels, event types, payload schemas for webhooks |
| `docs/vault.md` | Operators | Transit, KV, PKI, auth methods, rotation |
| `docs/private-ca.md` | Operators | Built-in CA, Vault PKI, trust distribution |
| `docs/api.md` | Integrators | Auth, scopes, pagination, errors; links to the served OpenAPI UI at `/api/docs` |
| `docs/security.md` | Operators, reviewers | Threat model, what each secret protects, KEK handling, mTLS, hook execution risks |
| `docs/operations.md` | Operators | Backup and restore, KEK rotation, agent CA rotation, upgrades, metrics reference, health endpoints |
| `docs/development.md` | Developers | Repo layout, make targets, code generation, running tests and e2e, adding a provider, target, notifier, or signer |
| `docs/adr/NNNN-*.md` | Developers | One Architecture Decision Record per non-obvious choice (lego in-process, envelope encryption, WS transport, river, no SSE) |

Rules: every UI tooltip "Learn more" link points to an anchor in these docs, so a feature is not done until its doc section exists. Every public Go package has a package comment. The OpenAPI spec has a description on every operation and field. Code generation output is committed, and CI fails if `make generate` changes anything.

## Execution order

1. Write this design to `docs/design.md`, create `docs/PROGRESS.md`, `CHANGELOG.md`, and a stub `README.md`, and commit (author metril).
2. Invoke `superpowers:writing-plans` to produce the Phase 1 implementation plan at `docs/superpowers/plans/`, commit it.
3. Execute Phase 1 with subagent-driven development (Sonnet implements, Opus reviews), TDD throughout, one commit per task, PROGRESS.md and docs updated in each.
4. Repeat spec → plan → implement for Phases 2 through 7 in order.
