# Web UI

The chrome, the dashboard and the fleet screens: Overview, Clients, the command palette.

## Sign in

The login page shows **Sign in with single sign-on** when Settings → Authentication has it enabled; the local admin password sits behind **Break-glass login**. Without single sign-on the password form is shown directly. A failed single sign-on returns here with a one-line reason (expired or interrupted sign-in, refused by the identity provider, account disabled, or not configured).

## Overview

`/o/:org/overview` is the landing page after sign-in. It shows, top to bottom:

- **Health strip** — appears only when `/readyz` reports a failing check (for example, the KEK not loaded); silent once the server is healthy.
- **Status tiles** — a count per certificate status (Active, Pending, Failed, Expired). Each tile is a filter: it links to the certificates list with that status pre-selected, not a modal or a drill-down page.
- **Needs attention** — one row per certificate that wants a look, most urgent first: expired, then waiting on manual DNS, then failed, then overdue for renewal. A certificate waiting on manual DNS is pinned at the top as its own card with the TXT records to add; the rest list the cause (the failure's first line, or how overdue) with an inline **Renew now**.
- **Expiry horizon** — one tick per certificate at its expiry, over the next 90 days, coloured by state, with the renewal window shaded behind it. Drag across the strip to list every certificate expiring in that range.
- **Upcoming renewals** and **Recent activity** side by side: certificates due in the next 7 days, and the last 20 audit events (shown to roles that can read the audit log; each links to the event on the Audit log page).

Below `md` width, the needs-attention queue and upcoming renewals render as stacked card rows instead of a table line, and the horizon scales to the screen width.

## Clients

`/o/:org/clients` lists the org's agents: connection (Online, Offline, Never connected, Revoked), site, agent version, grants, drift and failed counts, and last seen. Filter by status and site (kept in the URL as `?status=` and `?site=`; a site is a filter, never a scope), search by name or hostname, sort by name, connection or last seen, and save views. Below `md` width the list renders as cards. Under All orgs the list is read-only with an Org column. Each row opens the client. **Enrol client** takes a name and an optional site, then shows the one-time token with its agent URL and expiry, a `docker run` line and a Compose file to copy, and a live panel that waits for the agent (checked every 2 seconds) and shows its host once it connects. An expired token offers **New token**. The token is shown once and never stored in the browser. Once the agent connects, **Grant certificate** goes straight to the grant sheet.

## Client detail

`/o/:org/clients/:id/:tab`. The header shows the connection (Connected, Online (pull) for an agent that pulls without a live connection, Offline since a time, Never connected, Revoked), hostname, site, agent version and platform, the agent certificate's expiry (highlighted under 14 days) and the capabilities the agent reported. **Certificates** (the default tab) lists the client's grants: delivery (push or pull), layout, deploy target, hooks, auto-remediation and the deployment state (Pending, Deployed, Failed, Drift). Open a row to compare the files the server expects with what the agent last reported, see the agent's error, and **Redeploy**; the open row is kept in the URL (`?open=`). **Remove** asks for the certificate's name; the agent deletes the files on its next sync. **Grant certificate** picks one or more certificates, push or pull delivery, a layout and/or a deploy target, hooks in run order (a numbered list under the hook chips, reordered with Move up and Move down), and whether drift is repaired automatically. Each certificate becomes its own grant; if some fail (for example one is already granted) the others are kept and the sheet lists why. The pencil on a row edits a grant; its certificate cannot change. **Settings** renames the client and moves it between sites, and holds **Re-enrol** (a new one-time token, shown in a dialog; the agent is disconnected until it uses it), **Revoke** (the agent is refused from then on; files on the host stay) and **Delete** (only for revoked or never-enrolled clients). Each asks you to type the client's name. **Hooks** is the client's hook run history: when, which hook, phase, the command, exit status (Not run when the agent refused it or it timed out), duration, and its output. **Activity** lists audit events that mention the client, including those the agent recorded itself (enrolment, deployments, drift), with a link to the same filter on the Audit log page.

## Delivery

`/o/:org/delivery` holds what grants use, in tabs. **Deploy targets** lists each target's type, where it runs (the agent), its directory and how many grants use it. **Add target** picks a type and fills the form the type publishes (for Traefik: the directory the agent writes to, the same directory as Traefik sees it, whether this is the default certificate, and the TLS stores). A target in use cannot be deleted; the delete button says how many grants use it. Viewers can open a target read-only. Delivery is per org, so it is not offered under All orgs.

**File layouts** describe the files an agent writes for a grant, in order: an absolute path, the PEM parts joined into it (cert, chain, fullchain, key, combined), owner, group and mode. The editor checks paths as you type once you have tried to save (absolute, no `.` or `..`, not a directory, no duplicates) and warns when a file holding a private key is readable by every user. Layouts in use cannot be deleted.

## Settings → General

Base URL, then **Organizations**: admins add (slug derived from the name, "all" reserved), rename, and delete orgs (type the slug; an org that still holds certificates, credentials, accounts, CAs, sites, bindings or API keys is refused and the dialog lists them). **Sites** opens a sheet to add, rename and delete an org's sites.

## Settings → Access

Three tabs, kept in the URL (`?tab=users|bindings|keys`). **Users** lists everyone who has signed in with their source, groups and last sign-in; admins disable a user with the status switch (type the name to confirm). Your own switch is locked. Below `md` width the list renders as stacked card rows instead of a table, and a search box filters the list (also kept in the URL as `?q=`). Settings → Access itself is only offered in the nav to callers who can read users somewhere.

**Role bindings** lists every grant you can see, filterable by subject type (?type=). **Add binding** picks a user, types a group name, or picks an API key, plus a role and a scope (one org, or All orgs for global admins); an API key's scope is fixed to that key's own. Removing a binding asks you to type the subject's name; the last global admin binding held by a user cannot be removed.

**API keys**: name, key prefix, permissions, scope, creator, expiry, last use and status. **New API key** takes a name, a scope, permission chips (greyed out where your role does not reach) and an expiry (30 days, 90 days, 1 year, never, or a custom date — rejected inline if it's in the past). The token appears once in a dialog that stays open until you switch on Stored safely. Revoke asks for the key's name. Filterable by status (Active, Expired, Revoked, kept in the URL) with a search box and saved views; below `md` width the list renders as stacked card rows.

## Settings → Authentication

The redirect URI to register (copy button), the single sign-on form rendered from the section schema (the client secret shows Stored with Replace), **Test connection** for the issuer currently in the form, and **Group mappings**: group-to-role bindings, the same rows as group bindings in Access.

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

Press `Ctrl`/`Cmd` `K` from anywhere in the app to open it. Type to jump straight to a certificate by its name, common name, or any SAN; jump to any Phase 1 page (Certificates, Issuers, Settings sections); or run **New certificate** or **Renew `<name>`** without leaving the keyboard.
