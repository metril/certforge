# Web UI

The chrome, the dashboard and the fleet screens: Overview, Clients, the command palette.

## Sign in

The login page shows **Sign in with single sign-on** when Settings → Authentication has it enabled; the local admin password sits behind **Break-glass login**. Without single sign-on the password form is shown directly. A failed single sign-on returns here with a one-line reason (expired or interrupted sign-in, refused by the identity provider, account disabled, or not configured).

## Overview

`/o/:org/overview` is the landing page after sign-in. It shows, top to bottom:

- **Health strip** — appears only when `/readyz` reports a failing check (for example, the KEK not loaded), a degraded one (for example, a configured Vault section that answered but isn't fully healthy — the server can still be ready; a warning row links to Settings → Integrations), or when the agent listener certificate has under 14 days left (with a link to Settings → Agents); silent once the server is healthy.
- **Status tiles** — a count per certificate status (Active, Pending, Failed, Expired). Each tile is a filter: it links to the certificates list with that status pre-selected, not a modal or a drill-down page.
- **Needs attention** — one row per problem that wants a look, most urgent first: expired, waiting on manual DNS, issuance failed, deploy failed, drift, overdue for renewal, a client offline while it holds grants, and an agent certificate close to expiry. A certificate waiting on manual DNS is pinned at the top as its own card with the TXT records to add; certificate rows list the cause with an inline **Renew now**; client rows link to the client with one fix (Review, Open, or Re-enrol).
- **Expiry horizon** — one tick per certificate at its expiry, over the next 90 days, coloured by state, with the renewal window shaded behind it. Drag across the strip to list every certificate expiring in that range.
- **Upcoming renewals** and **Recent activity** side by side: certificates due in the next 7 days, and the last 20 audit events (shown to roles that can read the audit log; each links to the event on the Audit log page).

Below `md` width, the needs-attention queue and upcoming renewals render as stacked card rows instead of a table line, and the horizon scales to the screen width.

## Clients

`/o/:org/clients` lists the org's agents: status (Pending, Active, Revoked), connection (Online, Offline, Never connected), site, agent version, grants, drift and failed counts, and last seen. Filter by status and site (kept in the URL as `?status=` and `?site=`; a site is a filter, never a scope), search by name or hostname, sort by name, status or last seen, and save views. Below `md` width the list renders as cards. Under All orgs the list is read-only with an Org column. Each row opens the client. **Enrol client** takes a name and an optional site, then shows the one-time token with its agent URL and expiry, a `docker run` line and a Compose file to copy, and a live panel that waits for the agent (checked every 2 seconds) and shows its host once it connects. An expired token offers **New token**. The token is shown once and never stored in the browser. Once the agent connects, **Grant certificate** goes straight to the grant sheet.

## Client detail

`/o/:org/clients/:id/:tab`. The header shows the connection (Connected, Online (pull) for an agent that pulls without a live connection, Offline since a time, Never connected, Revoked), hostname, site, agent version and platform, the agent certificate's expiry (highlighted under 14 days) and the capabilities the agent reported. **Certificates** (the default tab) lists the client's grants: delivery (push or pull), layout, deploy target, hooks, auto-remediation and the deployment state (Pending, Deployed, Failed, Drift). Open a row to compare the files the server expects with what the agent last reported, see the agent's error, and **Redeploy**; the open row is kept in the URL (`?open=`). **Remove** asks for the certificate's name; the agent deletes the files on its next sync, unless a switch is turned on to remove the grant at once instead of waiting for the agent. **Grant certificate** picks one or more certificates, push or pull delivery, a layout and/or a deploy target, hooks in run order (a numbered list under the hook chips, reordered with Move up and Move down), and whether drift is repaired automatically. Each certificate becomes its own grant; if some fail (for example one is already granted) the others are kept and the sheet lists why. The pencil on a row edits a grant; its certificate cannot change. **Settings** renames the client and moves it between sites, and holds **Re-enrol** (a new one-time token, shown in a dialog; the agent is disconnected until it uses it), **Revoke** (the agent is refused from then on; files on the host stay) and **Delete** (only for revoked or never-enrolled clients). Each asks you to type the client's name. **Hooks** is the client's hook run history: when, which hook, phase, the command, exit status (Not run when the agent refused it or it failed to start, Timed out when it ran past its timeout), duration, and its output. **Activity** lists audit events that mention the client, including those the agent recorded itself (enrolment, deployments, drift), with a link to the same filter on the Audit log page.

## Import and upload

The certificates list's **Import** menu, next to New certificate, offers **From acme.sh or certbot** (reads an acme.sh or certbot state directory and takes over its renewals — see [Import](certificates.md#import)) and **Upload PEM or PKCS#12** (`/o/:org/certificates/upload`). Both need `certs:write` and are hidden under All orgs, though Import stays in the header even when the list is empty.

The upload page takes a name, a PEM/PKCS#12 segmented choice, and either the leaf certificate and its chain plus an optional private key as PEM text, or a `.p12`/`.pfx` file (capped at 768 KiB in the browser) and its password. It lands on the new certificate's own page once uploaded — see [Upload](certificates.md#upload) for what the server does with it.

The import page (`/o/:org/certificates/import`) takes an archive dropzone (`.zip`/`.tar.gz`/`.tgz`, capped at 32 MiB in the browser) and a CA combobox, then Preview runs a dry run: a summary line and a table of every certificate the archive holds, each with a Create or Skip chip and, for a skip, its reason. Below `md` the table becomes a card per row. Import runs the same call for real; rows with a stored certificate then link to it, and a toast confirms the count — see [Import](certificates.md#import) for what the server does with the archive.

## Certificate detail

`/o/:org/certificates/:id/:tab`. **Download** opens a sheet with a version, a Format segmented control (PEM, DER, PKCS#12, JKS) and, below it, that format's parts or password. PEM and DER show a chip set of parts (DER omits `fullchain` and `combined`, which exist only as PEM); PKCS#12 and JKS show a generated 24-character password with Copy and Regenerate, a **Use my own password** switch that swaps in a password field with a show/hide button, an Encoding control for PKCS#12 (Modern or Legacy), and an Alias field for JKS. `key`, `combined`, and both key-bearing formats are disabled without the `keys:export` permission, or when the chosen version has no stored key; a notice above the download button says the export is recorded in the audit log. **Attempts** labels the `caa` and `rate_ledger` steps CAA check and Rate limits, and shows the current rate-ledger usage under a failed Rate limits step. A private-CA certificate's attempts show `account`, `verify`/`challenge`, `caa` and `rate_ledger` as Skipped, each with "not used by private CAs" as its reason.

An unmanaged certificate (uploaded — import takes over renewals, so an imported certificate is managed) shows a **Managed externally** chip next to its status; Renew now and Settings' Edit are disabled with a tooltip instead, and the header offers **Upload new version** in their place, opening a sheet with the same certificate/key fields as Upload. The Versions tab marks a keyless version with a **No key** chip. When the CA has an ARI window, the validity bar draws it as a bracket above the track; below the bar, a text row states the window and when it was last checked, with a help tip (not a tooltip on the bracket itself). For a certificate whose effective CA is a private CA (Built-in CA or Vault PKI), each issued version row also gets a **Revoke** action (disabled without `certs:issue`) behind a confirm dialog with a Reason picker; a revoked version shows a **Revoked** chip in its place.

## Certificate deployments

A certificate's **Deployments** tab lists every client that holds it: connection, site, delivery, the grant's layout and deploy target (each opens it under Delivery), deployment state, whether the installed files match the current version, and **Redeploy**. The client name opens that client with the grant expanded. The certificates list's **Grants** column counts these.

## Issuers

`/o/:org/issuers/cas` lists every certificate authority — ACME, Built-in CA and Vault PKI — with a **Type** chip (ACME, Built-in CA, Vault PKI) and an above-the-table segmented filter (All / ACME / Built-in CA / Vault PKI, kept in the URL as `?type=`, wrapping below `md`). Endpoint shows the ACME directory URL, the Built-in CA's common name, or the Vault mount/role; Expires shows the issuing certificate's validity (Built-in CA, Vault PKI) or a dash for ACME. Clicking an ACME row opens the edit sheet (`?edit=`); clicking a private CA's row opens its detail sheet (`?view=`) — see [private-ca.md](private-ca.md#model). An empty filtered view reads "No Built-in CA yet." (or Vault PKI), with **Add CA**.

**Add/Edit CA** starts with a **Type** segmented control (locked once created — the type cannot change), then Name, then a kind-specific body:

- **ACME** — the preset cards, directory URL, trust bundle and EAB fields, unchanged.
- **Built-in CA** — an **Import existing CA** switch. Off shows Subject (common name, organization, country), key type, root and issuing validity, and the always-editable "Max leaf validity" and "Publish CRL". On hides those and shows the issuing certificate chain and its private key as PEM. On edit, Subject/key type/validity are shown read-only (immutable after create) and the import fields disappear entirely; only "Max leaf validity" and "Publish CRL" are sent.
- **Vault PKI** — mount, role and leaf TTL. Without Settings → Integrations → Vault configured, an inline note links there; Save stays enabled (the server rejects the save).

The command palette's **Issuers: New private CA** jumps straight to a new Built-in CA (`?edit=new&kind=localca`), gated the same as **Issuers: CAs**.

**Private CA detail** (`?view=<id>`, Built-in CA and Vault PKI only) shows the issuing certificate's validity bar and expiry, a Download button for the trust bundle (`<SafeName>-ca.pem`), and an **Edit** button. Built-in CA adds Subject, key type, max leaf days, an Imported chip when applicable, its CRL URL (a "CRL off" chip or a "Set the base URL" link to Settings → General when unpublished), the revoked count, and a chip per retired issuer (serial, "until" date) that copies that issuer's own CRL URL, disabled when it has none. Built-in CA also has **Rotate issuing certificate**, disabled for imported CAs, behind a confirm dialog that issues a fresh intermediate from the held root.

## Delivery

`/o/:org/delivery` holds what grants use, in tabs. **Deploy targets** lists each target's type, where it runs (an agent, or the server itself), its directory and how many grants use it. **Add target** picks a type and fills the form the type publishes (for Traefik: the directory the agent writes to, the same directory as Traefik sees it, whether this is the default certificate, and the TLS stores). A target in use cannot be deleted; the delete button says how many grants use it. Viewers can open a target read-only. Delivery is per org, so it is not offered under All orgs.

**Vault KV** runs on the server, not an agent — CertForge writes a certificate's rendered files to it directly, so its grants are client-less. The type picker shows a "Runs on server" hint; its form has the Vault mount, a path template (with the `certforge/{org}/{name}` default), the four KV document field names, and an **Include private key** switch, which needs `keys:export` and shows disabled behind a tooltip without it. A server-run target's row gets a **Grants** action instead of being pickable from a client's own Grant sheet, where it shows disabled with a tooltip; its grants and their state (Pending, Deployed, Failed with the error) render as a chip wherever grants list, distinct from an agent grant's file-deployment chip.

**Grants** opens a server-run target's own detail sheet (its row's **Grants** action), since it takes no client. The header repeats its type, a "Runs on server" chip and, when the target writes the key, an "Includes key" chip, plus **Edit**. Its own Grants table lists each grant's certificate (linked), layout (or "Target files" for the target's own key names) and status chip; **Redeploy**, **Edit layout** and **Delete** (a confirm: data already written to Vault stays) sit behind `clients:write`; **Edit layout** also needs `keys:export` when the target includes the key, same as New server grant below. **New server grant** swaps the sheet to a small form — a certificate combobox (locked to those with a current version, disabled on edit) and an optional layout combobox, where any layout holding a PKCS#12, JKS or DER file shows disabled ("PEM layouts only", since a server deploy only ever renders PEM parts); it needs `clients:write`, and `keys:export` too when the target includes the key. The grants list polls only while one is still pending.

**File layouts** describe the files an agent writes for a grant, in order: an absolute path, a format (PEM, DER, PKCS#12 or JKS), owner, group and mode. PEM joins parts (cert, chain, fullchain, key, combined, extra) as chips; DER picks Certificate or Key; PKCS#12 picks an encoding and JKS takes an alias, both of them password-protected keystores holding the certificate, chain and key. A layout with any PKCS#12/JKS file stores one export password — a generated one on a new layout, or a write-only field showing **Stored** with Replace/Remove once one exists (Remove only shows when no file still needs it). Up to 10 **extra certificates** from the same org can be bundled in as the `extra` PEM part or as extra keystore entries; the editor checks paths as you type once you have tried to save (absolute, no `.` or `..`, not a directory, no duplicates) and warns when a file holding a private key is readable by every user. Layouts in use cannot be deleted.

**Hooks** are commands an agent runs before (pre-deploy; a failure stops the deploy) or after (post-deploy) writing a grant's files. The command is entered as an executable path plus one argument per row, never as a shell line; the warning next to Executable is a reminder that each agent runs it only if that exact path is in its `CF_HOOK_ALLOW`. A timeout (1 to 3600 seconds) stops runaway hooks.

## Alerts

`/o/:org/alerts` holds notification channels, external monitors and the events log, in tabs (Channels, Monitors, Events — Monitors and Events land in later tasks). **Channels** lists every notification channel: type, destination (the server-computed, non-secret summary — a host, recipients, or similar), the kinds it receives (up to three chips, then a `+N` with the rest in its tooltip, or "All events" when unset, plus a severity chip when the floor is above Info), an **Enabled** switch, and its last delivery (a status chip plus a relative time; "Never" before its first event or test). A global admin also sees other orgs' `allOrgs` channels, with that owner org named under the channel's name. **Add channel** opens the edit sheet (a later task); it and the Enabled switch need `alerts:write`, gated per channel's own org, and an `allOrgs` channel can only be switched by a global admin. An org is capped at 50 channels. Clicking a row opens it the same way.

## Settings → General

Base URL, then **Organizations**: admins add (slug derived from the name, "all" reserved), rename, and delete orgs (type the slug; an org that still holds certificates, credentials, accounts, CAs, sites, bindings or API keys is refused and the dialog lists them). **Sites** opens a sheet to add, rename and delete an org's sites.

## Settings → Access

Three tabs, kept in the URL (`?tab=users|bindings|keys`). **Users** lists everyone who has signed in with their source, groups and last sign-in; admins disable a user with the status switch (type the name to confirm). Your own switch is locked. Below `md` width the list renders as stacked card rows instead of a table, and a search box filters the list (also kept in the URL as `?q=`). Settings → Access itself is only offered in the nav to callers who can read users somewhere.

**Role bindings** lists every grant you can see, filterable by subject type (?type=). **Add binding** picks a user, types a group name, or picks an API key, plus a role and a scope (one org, or All orgs for global admins); an API key's scope is fixed to that key's own. Removing a binding asks you to type the subject's name; the last global admin binding held by a user cannot be removed.

**API keys**: name, key prefix, permissions, scope, creator, expiry, last use and status. **New API key** takes a name, a scope, permission chips (greyed out where your role does not reach) and an expiry (30 days, 90 days, 1 year, never, or a custom date — rejected inline if it's in the past). The token appears once in a dialog that stays open until you switch on Stored safely. Revoke asks for the key's name. Filterable by status (Active, Expired, Revoked, kept in the URL) with a search box and saved views; below `md` width the list renders as stacked card rows.

## Settings → Authentication

The redirect URI to register (copy button), the single sign-on form rendered from the section schema (the client secret shows Stored with Replace), **Test connection** for the issuer currently in the form, and **Group mappings**: group-to-role bindings, the same rows as group bindings in Access.

## Settings → Issuance defaults

Two tabs: **Global** (built-in, server-wide defaults) and the current org. Each org field shows a badge for where its value comes from (Default, Global or the org's own Override) with a hover chain listing every level; an unset field inherits from the level above and a change applies at each certificate's next renewal. Global and org each save independently.

The Global tab also carries a **Checks and limits** block, rendered straight from the server's `issuance` settings schema: a **Check CAA records** switch and a two-column grid of four rate limits (certificates per registered domain per week, duplicate certificates per week, failed validations per hour, new orders per 3 hours — 0 disables a limit). This section is global only and has its own Save; it does not appear on the org tab.

## Settings → Agents

The agents settings (the URL agents dial, extra listener names, token and agent certificate lifetimes, heartbeat and offline thresholds), then the **listener certificate** (its names, expiry and issuing CA) and the **agent CAs**. **Rotate** creates a new CA that signs new agent certificates; agents move over as they renew, and unused enrolment tokens keep working until the old CA is retired. A retiring CA can be **retired** once no agent still uses it; the listener certificate then switches to the newer CA and tokens pinned to the retired one are refused. Only global admins can change anything here.

## Settings → Integrations

The `vault` settings section (`GET`/`PUT /api/v1/settings/vault`) — how the server reaches Vault or OpenBao for private CAs on the `vaultpki` kind and the `vault-kv` deploy target, distinct from a Transit KEK (which is bootstrap configuration, not this section). Address, namespace, auth method (a segmented control between `token` and `approle`, each showing only the secret field it needs), the CA bundle as a mono textarea, and the per-request timeout. When the auth method or a stored `token`/`secretId` field isn't touched it goes out as the `__unchanged__` sentinel; a saved `PUT` that changes address or namespace without re-sending the secret its auth method needs comes back as a 422 next to that field.

**Test connection** logs in with whatever is currently in the form (again with an untouched secret sent as `__unchanged__`) without saving anything, and shows a status chip: **Connected** with the resulting token's TTL, Vault's version and its policies (as chips, capped at 5 with a `+N` overflow), or **Failed** with the server's own scrubbed error text. The result clears as soon as any field changes. Only `settings:write` can use Save or Test connection; a caller without it sees both disabled, never hidden.

When the server's own key-encryption key is a Transit KEK (`GET /keys/status` reports `kind: vault-transit`), a read-only **Transit KEK** line above the form shows the Vault address in use — set by environment variables, not this section.

## Settings → Backup and keys

The **Encryption key** card, fed by `GET /keys/status`: kind (Static or Vault Transit, with the Vault address when Transit), the key id, a canary chip (**Canary OK**/**Canary failed**), and previous keys still accepted for reading (`<kind> · <key id>` chips, or "None"). While a rewrap has ever run, a **Running**/**Finished**/**Failed** chip, its started/finished times and remaining count, and one thin progress bar per table (settings, CAs, ACME accounts, DNS credentials, output specs, agent CAs, certificate versions) showing rewrapped vs scanned. **Rewrap now** (`settings:write`) starts a fresh run; it's disabled while one is running, and disabled with a tooltip when there's no previous key and none has ever run. `GET /keys/status` is polled every 5 seconds only while a rewrap is running. Below the card, the escrow-confirmation switch from the `backup` settings schema.

## Audit log

`/o/:org/audit` lists events newest first: time, actor, action, resource, IP (and org in All orgs). Filters live in the URL as removable chips: search, action (or a whole group such as `session.*`), resource type, actor, and a date range. Clicking a row opens the event with a before/after diff for changes; a link with `?event=<id>` opens that event directly, even if it isn't on the currently loaded page. The chip in the header shows whether the hash chain verifies (checked at most once a minute) and is only shown to callers with a global role, since verifying the chain covers every org. **Export CSV** downloads the filtered events; the export itself is audited, and a one-line notice appears if the 100,000-row cap was hit. An org's view shows that org's events; global events (sign-ins, settings) appear under All orgs. Below `md` width the list renders as stacked card rows. Agent-originated events show the client's name as the actor.

## All orgs

Users with a global role get **All orgs** at the top of the org switcher (/o/all/…). Overview, Certificates and the Audit log then span every org you can read and are read-only: no create, renew, delete or bulk actions, and pages that need one org (Issuers, the certificate wizard and detail) redirect to the All orgs overview. Opening a certificate switches to its org.

## Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl` / `Cmd` `K` | Open the command palette. Pressing it again closes the palette. |
| `g` then `o` | Go to Overview |
| `g` then `c` | Go to Certificates |
| `n` then `c` | New certificate |

### Command palette

Press `Ctrl`/`Cmd` `K` from anywhere in the app to open it. Type to jump straight to a certificate by its name, common name, or any SAN; to clients by name or hostname; to any page (Certificates, Issuers, the Clients and Delivery pages, Settings sections including Settings → Agents); or run **New certificate**, **Import certificates** and **Upload certificate** (the same `certs:write` writers as New certificate, going straight to the Import and Upload screens), **Enrol client** (for roles that can enrol), or **Renew `<name>`** without leaving the keyboard. 5B adds **Issuers: New private CA** (a new Built-in CA, gated the same as **Issuers: CAs**), **Settings: Integrations** (the Vault section) and **Settings: Backup and keys** (the encryption key card). 6B adds **Alerts: Channels**, **Alerts: Monitors** and **Alerts: Events**, gated on `alerts:read`.
