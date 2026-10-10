# Overview

This page is a tour of the CertForge interface: the sidebar, the **Overview** dashboard with its **Needs attention** queue, the **Flow** map, the command palette, keyboard shortcuts and how side panels behave. Read it once and the other guide pages will feel familiar.

## Find your way around

The sidebar has three groups. Items you cannot use are hidden or disabled with a tooltip that says why.

| Group | Items |
|---|---|
| Operate | **Overview**, **Flow**, **Certificates**, **Clients** |
| Configure | **Issuers**, **Delivery**, **Alerts** |
| Govern | **Audit log**, **Settings** |

At the top of the sidebar:

- The **organization switcher** picks which organization you work in. Pages live under `/o/<slug>/…`. Global roles also get **All orgs** (see below).
- **Search** (`Ctrl K`) opens the [command palette](#command-palette).

At the bottom, the account menu has a **Theme** control (**System**, **Light** or **Dark**) and **Sign out**. On a narrow screen the sidebar collapses to a menu button or an icon rail.

The **Clients** item shows a count badge (a dot on the icon rail) when enrolments are waiting for your approval. See [Clients](clients.md#approval).

### All orgs

Users with a global role see **All orgs** at the top of the switcher. **Overview**, **Certificates**, **Clients**, **Audit log** and **Settings** then cover every organization you can read. This view is read-only and shows **All orgs · read-only** at the top: you cannot create, renew, delete or bulk-edit. Pages that need one organization (**Issuers**, **Flow**, **Delivery**, **Alerts**, the certificate wizard) show **Pick one organization**. Open a certificate and the switcher moves to its organization.

## Read the dashboard

**Overview** is the page you land on after signing in (`/o/<slug>/overview`). It has three blocks.

### Status row

One tile per certificate state: **Active**, **Pending**, **Failed** and **Expired**, each with a count. A tile is a filter: select it to open **Certificates** with that status already chosen.

Next to the tiles, a health strip appears only when something about the server needs a look:

- A failing readiness check, for example the encryption key is not loaded (**Server not ready**).
- A degraded check, for example Vault answered but is not fully healthy, or a scheduled backup has had no success in 7 days. A link jumps to **Integrations** or **Backups**.
- The agent listener certificate expires in under 14 days, with a link to **Settings → Agents**.

When the server is healthy the strip is not shown.

### Needs attention

One card listing every problem that wants a look, most urgent first. Each row has one action.

| Row | Meaning | Action |
|---|---|---|
| **Expired** | A certificate has expired | **Renew now** |
| **Awaiting approval** | A new agent enrolled and waits for an admin | **Review** (opens the approval list on **Clients**) |
| **Manual DNS** | A certificate waits for you to add TXT records | Pinned at the top as its own card with the records to add |
| **Failed** | Issuance or renewal failed | **Renew now** |
| **Mismatch** | An external monitor sees the wrong certificate | **Check now** |
| **Deploy failed** | A deployment to a client failed | **Review** |
| **Drift** | Files on a client differ from what CertForge expects | **Review** |
| **Overdue** | A certificate is past its renewal time | **Renew now** |
| **Unreachable** | An external monitor cannot connect | **Check now** |
| **Offline** | A client that holds grants is offline | **Open** |
| **Agent certificate** | A client's identity certificate expires soon | **Re-enrol** |

**Renew now** needs permission to issue certificates and is hidden under **All orgs**. Monitor rows appear only when you look at a single organization. With nothing to do the card says "Nothing needs attention." Under the list, **Upcoming renewals** shows certificates due in the next 7 days.

### Insights

Two tabs:

- **Expiry horizon** draws one tick per certificate at its expiry over the next 90 days, coloured by state, with the renewal window shaded behind it. Drag across the strip to list every certificate expiring in that range.
- **Recent activity** shows the last 20 audit events; each links to the [Audit log](audit.md). Only roles that can read the audit log see this tab.

## Trace a certificate on the Flow map

**Flow** (`/o/<slug>/flow`) is a read-only map of how one organization makes and uses certificates. Lanes run left to right: Issuers (CAs, ACME accounts, DNS credentials), Certificates, Delivery (layouts, targets, hooks), Clients, and Alerts (channels).

1. Select a node. Its path stays at full strength and everything else dims. Press Escape or select the node again to clear.
2. A certificate shows its issuers, its delivery nodes, the clients each delivery reaches, and the channels that would receive its events. An issuer shows every certificate that uses it.
3. A path panel above the map lists the stages in order, each with an **Open** link to the item.

Each node carries one status chip. Issuer nodes read **In use** or **Unused**; a private CA also reads **Expiring** or **Expired**; channels read **Delivering**, **Delivery pending**, **No deliveries yet**, **Disabled** or **Failing**; other nodes read Healthy, Expiring, Expired, Failed, Drift, Pending or Idle.

Narrow the map with the toolbar:

- **Search** matches node names.
- **Show** switches between **All** and **Problems** (failed, expired, in drift or expiring nodes and their paths).
- Lane headings collapse; **Collapse all** and **Expand all** toggle every lane.

Filters, the selected node and collapsed lanes are kept in the page URL, so you can share a view. A lane you cannot read shows "No access"; a **Truncated** chip means the server capped the map. Below 1024 pixels the lanes stack and selecting a node filters them to its path.

## Command palette

Press `Ctrl K` (`Cmd K` on macOS) anywhere to open it, or select **Search** in the sidebar. Press it again to close. Type to filter.

| You type | You get |
|---|---|
| A certificate name, common name or any name on it | Jump to that certificate |
| A client name or hostname | Jump to that client |
| A page name | **Overview**, **Flow**, **Certificates**, **Clients**, **Issuers: CAs**, **Issuers: ACME accounts**, **Issuers: DNS credentials**, **Delivery: Deploy targets**, **Delivery: File layouts**, **Delivery: Hooks**, **Alerts: Channels**, **Alerts: Monitors**, **Alerts: Events**, **Audit log** |
| A settings section | **Settings: General**, **Access**, **Authentication**, **Issuance defaults**, **Agents**, **Integrations**, **Backups** |
| An action | **New certificate**, **Import certificates**, **Upload certificate**, **Enrol client**, **Issuers: New private CA**, **Settings: Back up now**, and **Renew** `<certificate name>` |

Entries you lack permission for are left out. Under **All orgs** only **Overview**, **Certificates**, **Clients**, **Audit log** and the settings pages are offered.

## Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl` / `Cmd` + `K` | Open or close the command palette |
| `g` then `o` | Go to **Overview** |
| `g` then `c` | Go to **Certificates** |
| `n` then `c` | New certificate |

Press the two letters one after the other, within about a second. Shortcuts are ignored while you type in a field or while a dialog, panel or menu is open.

## Side panels

Create and edit forms open in a panel from the right. A panel never closes when you click outside it. If you changed something, closing it (Escape, the X or **Cancel**) asks **Discard changes?**; choose Cancel there to keep your draft or **Discard** to throw it away. Saving closes the panel without asking. Leaving the page by another route (Back, a sidebar link) asks the same question; a reload or closed tab shows the browser's own prompt.

Long forms keep rarely changed fields in a collapsed **Advanced** section. Its badge counts values that differ from their defaults, and it opens by itself if one of them has an error.

## Common problems

**A sidebar item is greyed out.** You are in **All orgs** and the page needs one organization, or your role cannot use it. Hover the item for the reason, then pick an organization from the switcher.

**There is no Recent activity tab.** Your role cannot read the audit log. You need the auditor or admin role.

**A shortcut does nothing.** Focus is in a text field or a dialog is open. Click the page background and try again.


## See also

- [Certificates](certificates.md): the list, the wizard and the detail page.
- [Clients](clients.md#approval): the approval list the badge points to.
- [Audit log](audit.md)
- [Settings](settings.md)
