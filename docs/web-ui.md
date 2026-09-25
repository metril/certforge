# Web UI

The chrome and dashboard shared by every screen: the Overview page and the command palette.

## Sign in

The login page shows **Sign in with single sign-on** when Settings → Authentication has it enabled; the local admin password sits behind **Break-glass login**. Without single sign-on the password form is shown directly. A failed single sign-on returns here with a one-line reason (expired or interrupted sign-in, refused by the identity provider, account disabled, or not configured).

## Overview

`/o/:org/overview` is the landing page after sign-in. It shows, top to bottom:

- **Health strip** — appears only when `/readyz` reports a failing check (for example, the KEK not loaded); silent once the server is healthy.
- **Status tiles** — a count per certificate status (Active, Pending, Failed, Expired). Each tile is a filter: it links to the certificates list with that status pre-selected, not a modal or a drill-down page.
- **Needs attention** — one row per certificate that wants a look, most urgent first: expired, then waiting on manual DNS, then failed, then overdue for renewal. A certificate waiting on manual DNS is pinned at the top as its own card with the TXT records to add; the rest list the cause (the failure's first line, or how overdue) with an inline **Renew now**.
- **Expiry horizon** — one tick per certificate at its expiry, over the next 90 days, coloured by state, with the renewal window shaded behind it. Drag across the strip to list every certificate expiring in that range.
- **Upcoming renewals** — certificates due to renew in the next 7 days.

Below `md` width, the needs-attention queue and upcoming renewals render as stacked card rows instead of a table line, and the horizon scales to the screen width.

## Settings → Access

Three tabs, kept in the URL (`?tab=users|bindings|keys`). **Users** lists everyone who has signed in with their source, groups and last sign-in; admins disable a user with the status switch (type the name to confirm). Your own switch is locked. Below `md` width the list renders as stacked card rows instead of a table, and a search box filters the list (also kept in the URL as `?q=`). Settings → Access itself is only offered in the nav to callers who can read users somewhere.

**Role bindings** lists every grant you can see, filterable by subject type (?type=). **Add binding** picks a user or types a group name, a role, and a scope (one org, or All orgs for global admins). Removing a binding asks you to type the subject's name; the last global admin binding held by a user cannot be removed.

## Settings → Authentication

The redirect URI to register (copy button), the single sign-on form rendered from the section schema (the client secret shows Stored with Replace), **Test connection** for the issuer currently in the form, and **Group mappings**: group-to-role bindings, the same rows as group bindings in Access.

## Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl` / `Cmd` `K` | Open the command palette. Pressing it again closes the palette. |
| `g` then `o` | Go to Overview |
| `g` then `c` | Go to Certificates |
| `n` then `c` | New certificate |

### Command palette

Press `Ctrl`/`Cmd` `K` from anywhere in the app to open it. Type to jump straight to a certificate by its name, common name, or any SAN; jump to any Phase 1 page (Certificates, Issuers, Settings sections); or run **New certificate** or **Renew `<name>`** without leaving the keyboard.
