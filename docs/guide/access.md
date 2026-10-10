# Access

This page covers who can do what in CertForge: organizations and sites, users, roles, API keys and single sign-on. Most of it lives under **Settings → Access**, **Settings → Authentication** and **Settings → General**.

## Before you start

- A **role** is a named set of permissions. You give a role to a user, to an identity-provider group, or to an API key by creating a **role binding**.
- A binding has a **scope**: one organization, or **All orgs** (global). Only global bindings can use the actions that affect the whole server, such as editing settings or creating CAs.
- Changes to bindings apply on the next request.

## Roles

| Role | What it can do |
|---|---|
| **Viewer** | Read everything except secrets and the audit log. |
| **Auditor** | Everything a viewer can, plus read the **Audit log**. |
| **Operator** | Everything a viewer can, plus issue, renew and edit certificates, ACME accounts, DNS credentials, clients and grants, delivery layouts, targets and hooks, and alerts. |
| **Org admin** | Everything inside one organization (bindings, API keys, sites) except the actions below that need a global role. |
| **Admin** | Everything, in every organization. |

Only a global **Admin** can: edit server settings, create or delete organizations, create or change CAs, download private keys, reveal DNS credential secrets and manage users. Where you lack a permission a button is disabled and its tooltip names the permission it needs, for example `cas:write`.

Handing a private key to a client (a layout with a key file, or any agent deploy target) also needs the key-export permission, so an operator can create certificate-only grants but not key-bearing ones.

## Create an organization and sites

An organization separates certificates, credentials and access. Sites are labels inside an organization (for example a data centre) that you can filter clients by. A site is a filter, never a permission boundary.

1. Open **Settings → General**. Below the server settings is the **Organizations** card.
2. Select **New organization**, enter a **Name**, and save. The slug is made from the name; it appears in URLs and never changes. `all` is reserved.
3. To add sites, select **Sites** on the organization's row, type a name under **New site** and select **Add**. Use the pencil and bin icons on a site to rename or delete it.
4. To rename an organization, use the pencil on its row.
5. To delete an organization, use the bin icon and type the slug to confirm. An organization that still holds certificates, credentials, accounts, CAs, sites, role bindings, active API keys, channels or monitors is refused, and the dialog lists what is left. Its issuance defaults and revoked-key history are removed with it.

## Manage users

**Settings → Access → Users** lists everyone who has signed in, plus the local admin: name, email, source, groups, last sign-in and status.

CertForge never creates users by hand. A person appears after their first single sign-on, or as the local admin created by the setup wizard. A new single sign-on user has no access until a role binding or group mapping gives them a role.

To disable a user, turn off their status switch and type their name to confirm. Their sessions end at once and the API keys they created stop working. Turn the switch back on to re-enable them. Your own switch is locked, and users are never deleted. The page offers a search box; on a narrow screen the table becomes cards.

If you hold the user-read permission only in one organization (an **Org admin**), you see other users' name, email, status and creation time, but not their groups, source or last sign-in.

## Grant a role

**Settings → Access → Role bindings** lists every binding you can see. Filter by subject type, organization or text.

1. Select **Add binding**.
2. Under **Subject**, choose **User**, **Group** or **API key**. Pick the user or key, or type the group name exactly as your identity provider sends it.
3. Choose a **Role**.
4. Choose a **Scope**: one organization, or **All orgs** (global admins only). An API key's scope is fixed to the key's own.
5. Save.

To remove a binding, use the remove icon and type the subject's name. You cannot remove the last global **Admin** binding a user holds.

Group bindings match the groups recorded at the user's last sign-in. Adding the binding to a group does not affect someone until they sign in again.

## API keys

An API key lets a script or `cfctl` call the API. A key can do at most what its creator can do right now, narrowed to the permissions you tick and to one organization if you choose. It stops working when it is revoked, expired, or when its creator is disabled. Keys cannot create keys.

### Create a key

1. Open **Settings → Access → API keys** and select **New API key**.
2. Enter a **Name**, for example `ci-deploy`.
3. Choose a **Scope**: one organization or **All orgs**.
4. Tick the **Permissions** (shown as chips). Permissions outside your own role are greyed out.
5. Choose **Expires**: 30 days, 90 days, 1 year, **Never**, or **Custom** date. If an administrator set a maximum lifetime, **Never** is not offered and the longest choice is that maximum.
6. Save. The token appears once. Copy it, switch on **Stored safely**, and select **Done**. Only a hash is kept, so a lost key needs a new one.

| Permission | What it allows |
|---|---|
| `certs:read`, `certs:write`, `certs:issue` | View, edit and issue certificates |
| `keys:export` | Download private keys |
| `dnscreds:reveal` | Show a stored DNS credential secret |
| `clients:read`, `clients:write` | View clients; create and change clients and grants |
| `delivery:read`, `delivery:write` | View, and change layouts, targets and hooks |
| `alerts:read`, `alerts:write` | View, and change channels and monitors |
| `admin` | Everything the creator can do |

### Use a key

Send the token as a bearer credential:

```bash
curl -H "Authorization: Bearer cf_<prefix>_<secret>" https://certs.example.com/api/v1/orgs
```

For the command-line client see [cfctl](../reference/cfctl.md). Any other `Authorization` scheme is ignored and the request is treated as an ordinary browser session.

### List and revoke keys

The list shows name, key prefix, permissions, scope, creator, expiry, last use and status (**Active**, **Expired** or **Revoked**). Filter by status, search by name, and save views. To revoke, use **Revoke** on the row and type the key's name.

Two limits protect the server: a maximum key lifetime and a maximum number of active keys per user. Both are set in **Settings → Authentication** (see the table below); the defaults are no maximum lifetime and 50 active keys.

## Single sign-on

CertForge signs users in through any OpenID Connect provider. Users are matched by the provider's issuer and subject, never by email.

### Set it up

1. In your identity provider, register a client for CertForge. Open **Settings → Authentication** and copy the **Redirect URI** (it ends in `/api/v1/auth/oidc/callback`). Register that exact address.
2. In **Settings → Authentication**, fill in the form and save:

   | Field | What it does | Default |
   |---|---|---|
   | **Single sign-on** | Shows the single sign-on button on the login page | off |
   | **Issuer URL** | The provider's issuer; CertForge reads its discovery document. Must be `https` unless the host is loopback | none |
   | **Client ID** | The client you registered | none |
   | **Client secret** | Leave empty for a public client using PKCE only. Stored sealed; shows as stored with **Replace** | none |
   | **Scopes** | Must include `openid` | `openid profile email groups` |
   | **Groups claim** | The ID-token claim that lists the user's groups. A dotted path such as `realm_access.roles` reads a nested claim | `groups` |
   | **Session lifetime (hours)** | How long a sign-in lasts; applies to new sessions | 12 |
   | **Trusted proxies** | Addresses or CIDRs of reverse proxies whose `X-Forwarded-For` header is believed | none |
   | **Login rate limit (per minute)** | Login attempts per client address; `0` disables the limit | 10 |
   | **Login rate limit burst** | Attempts allowed in one burst | 5 |
   | **API key maximum lifetime (days)** | Longest lifetime of a new key; `0` is unlimited | 0 |
   | **Active API keys per user** | Most active keys one user may hold; `0` is unlimited | 50 |

   Bounds for every field are in [Configuration](../reference/configuration.md#authentication).

3. Select **Test connection**. It fetches the issuer's discovery document and signing keys without signing anyone in.
4. Turn on **Single sign-on** and save. Issuer URL and Client ID are required when it is on.

The login page then shows **Sign in with single sign-on**. The local admin password stays available behind **Break-glass login**.

### Map groups to roles

Under **Group mappings** on the same page, select **Add mapping**, type the group name exactly as the provider sends it, and choose a role and scope. Mappings are role bindings with a group subject, so they also show in **Role bindings**. Only global admins can add them.

A user gets the roles of every group listed at their last sign-in. Without any matching group or binding they have no access.

## Common problems

**Sign-in returns to the login page with a message.** The message names the cause: "The sign-in expired or was interrupted" (start again), "The identity provider refused the sign-in", "Your account is disabled" (an admin disabled you), "Single sign-on is not configured", or a generic "Single sign-on failed. Try again." (too many attempts from one address also ends here; wait a minute).

**Group mappings do nothing.** The group name must match the claim exactly, and the **Groups claim** must be the claim your provider actually fills. Make sure the `groups` scope is requested and that the user signed in again after the mapping was added.

**You cannot save the issuer.** Plain `http://` issuers are accepted only on `localhost` and loopback addresses. For a test stack on another host, the server must be started with `CF_OIDC_ALLOW_INSECURE_ISSUER=true`.

**An API key stopped working.** It was revoked, it expired, or the user who created it was disabled.

**Audit log shows the wrong client address.** Add your reverse proxy to **Trusted proxies**. Without it, `X-Forwarded-For` is ignored.

## See also

- [Settings](settings.md)
- [Audit log](audit.md): sign-ins, binding changes and key creation are all recorded.
- [Security model](../operations/security-model.md)
- [Configuration](../reference/configuration.md#authentication)
- [cfctl](../reference/cfctl.md)
