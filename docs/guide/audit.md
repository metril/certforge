# Audit log

The audit log is a permanent record of who did what in CertForge: sign-ins, setting changes, certificate actions, agent enrolments and deployments. Events cannot be edited or deleted, and a built-in check proves nobody has tampered with them. Open it from **Audit log** in the sidebar.

## Before you start

- You need the **Auditor** or **Admin** role (or **Org admin** for your own organization). Other roles do not see the page.
- An organization's view shows that organization's events. Events that belong to no organization, such as sign-ins and server settings, appear only under **All orgs**, which needs a global role.

## Read the log

Events are listed newest first with these columns:

| Column | Meaning |
|---|---|
| **Time** | When it happened |
| **Actor** | The user or API key that acted. Agents show the client's name; scheduled work shows `system` |
| **Action** | What happened, for example `certificate.renew` (see [Actions](#actions)) |
| **Resource** | The type and id of the thing it happened to |
| **IP** | The client address. It comes from `X-Forwarded-For` only when the request arrived through a trusted proxy ([Access](access.md#single-sign-on)) |
| **Org** | The organization (under **All orgs** only) |

Select a row to open the event. Changes show a **Before** and **After** table of the fields that changed; other events show the raw details, with **Copy JSON**. A link ending in `?event=<id>` opens that event directly, even if it is not on the page you loaded. If the event does not exist or your role cannot read it, the page says so.

On a narrow screen the list becomes stacked cards.

## Find an event

Use the filter bar. Every filter is kept in the page URL, so you can bookmark or share a search. **Clear filters** resets them.

| Filter | What it does |
|---|---|
| **Search** | Case-insensitive text match on action, resource, actor, IP or details |
| **Action** | One action, or a whole group such as `session.*` |
| **Resource** | One resource type, for example `certificate` or `client` |
| **Actor** | One user |
| **From**, **To** | A date range |

While you search with text, **From** defaults to 30 days back and the page says "Last 30 days while searching". Pick an earlier date to widen it. Text search scans the whole log, so a search that takes too long is refused; add a date range and try again.

## Export events

Select **Export CSV** to download the events that match your filters. The export is itself recorded as `audit.export`. It stops at 100,000 rows and shows "The export hit the 100,000-row cap"; narrow the filters to get the rest. If a query fails halfway, **Export incomplete** appears and the file is missing events after that point; try again. Cells that start with `=`, `+`, `-` or `@` are escaped so a spreadsheet cannot run them.

## Check the log is intact

The **Chain verified** chip in the page header shows that every event links to the one before it with a keyed hash, so an edited or removed event is detected. It is shown only to users with a global role, because the check covers every organization, and is refreshed at most once a minute.

If the chain does not match, the chip turns red and says where, for example **Chain broken at #1234**, **Chain broken: newest events removed (from #…)**, or **Chain broken: head anchor missing**. That means the log was changed outside CertForge. Treat it as a security incident: keep the database, compare it with a backup, and see [Security model](../operations/security-model.md). If the chip shows **Chain status unavailable**, the check itself could not run; reload and try again.

## Actions

The **Action** filter offers each group and each action below. Several names are recorded by the server and agents on behalf of other features.

| Group | Actions |
|---|---|
| Sign-in | `session.login`, `session.login_failed`, `session.logout`, `session.revoked` (other sessions ended after a new sign-in or a user was disabled), `auth.local_admin_password_set` (the admin password was set at setup or by `bootstrap-admin`) |
| Older sign-in names | `auth.login`, `auth.login_failed`, `auth.logout`. Earlier versions recorded sign-ins under these names, so they still appear on old entries |
| Setup and settings | `setup.complete`, `settings.update`, `issuance_defaults.update`, `smtp.test` |
| Organizations and access | `org.create`, `org.update`, `org.delete`, `site.create`, `site.update`, `site.delete`, `user.update`, `role_binding.create`, `role_binding.delete`, `api_key.create`, `api_key.revoke` |
| Certificates | `certificate.create`, `certificate.update`, `certificate.delete`, `certificate.renew`, `certificate.revoked`, `certificate.import`, `certificate.manual_dns_confirmed`, `certificate.key_exported` (recorded before a key-bearing download) |
| Issuers | `ca.create`, `ca.update`, `ca.delete`, `ca.rotate`, `acme_account.create`, `acme_account.delete`, `dns_credential.create`, `dns_credential.update`, `dns_credential.delete`, `dns_credential.test`, `dns_credential.secret_revealed` |
| Clients and enrolment | `client.create`, `client.update`, `client.delete`, `client.revoke`, `client.reenroll` (a new token was issued), `client.enrol_requested` (an agent presented a valid token and awaits approval), `client.enrol_approved`, `client.enrol_rejected`, `client.enrolled` (the agent received its certificate), `client.cert_renewed` (an agent renewed its identity certificate) |
| Agent CA | `agent_ca.rotate`, `agent_ca.retire` |
| Delivery | `grant.create`, `grant.update`, `grant.delete`, `grant.redeploy`, `grant.bundle_fetched` (a client downloaded its files), `deployment.ok`, `deployment.failed`, `deployment.drift`, `layout.*`, `deploy_target.*`, `hook.create`, `hook.update`, `hook.delete`, `hook.run` |
| Alerts | `channel.create`, `channel.update`, `channel.delete`, `channel.test`, `monitor.create`, `monitor.update`, `monitor.delete`, `monitor.check` |
| Backup and keys | `backup.created`, `backup.failed`, `kek.rewrap_started`, `kek.rewrap_finished` |
| The log itself | `audit.export`, `audit.anchor_initialized` (the tamper-check anchor was created on upgrade) |

`layout.*` and `deploy_target.*` each stand for `create`, `update` and `delete`.

The events feed under **Alerts** is separate: it lists notifications sent to your channels ([Alerts](alerts.md)), not audit events.

## Common problems

**The Chain chip is missing.** Only global roles see it. Switch to **All orgs** as a global admin.

**An event I expect is not there.** Check the organization you are in: sign-ins and settings changes are global and show only under **All orgs**. Check **From** and **To**, and the filter chips.

**Search says it took too long.** Add a **From** date and search again.

**The IP column shows the proxy's address.** Add the proxy to **Trusted proxies** in **Settings → Authentication**.

## See also

- [Access](access.md): roles and API keys.
- [Security model](../operations/security-model.md): how the chain is built.
- [Settings](settings.md)
