import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { Action } from '@/lib/permissions';
import { server } from '@/test/server';
import { authHandlers, makeCert, makeClient, meWith, org, org2, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// Every real role's read actions come as a fixed VIEWER block (see
// lib/permissions.ts: any role granting certs:read also grants
// cas:read/accounts:read/dnscreds:read), so there is no real role that has
// "only certs:read" to bind a test user to — this overrides `can`/
// `canAnywhere` directly to isolate the palette's own per-entry gating from
// the app's actual role compositions. `permissionOverride` unset (the
// default) passes every call through to the real implementation, so every
// other test in this file is unaffected.
let permissionOverride: { can?: (action: Action) => boolean; canAnywhere?: (action: Action) => boolean } | null = null;
vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>();
  return {
    ...actual,
    can: (me: Parameters<typeof actual.can>[0], action: Action, orgId?: string | null) =>
      permissionOverride?.can ? permissionOverride.can(action) : actual.can(me, action, orgId),
    canAnywhere: (me: Parameters<typeof actual.canAnywhere>[0], action: Action) =>
      permissionOverride?.canAnywhere ? permissionOverride.canAnywhere(action) : actual.canAnywhere(me, action),
  };
});
afterEach(() => {
  permissionOverride = null;
});

function certificateHandlers(cert: ReturnType<typeof makeCert>) {
  return [
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [cert], nextCursor: null })),
    http.get(url(`/orgs/org-1/certificates/${cert.id}`), () => HttpResponse.json(cert)),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({})),
  ];
}

it('opens with Ctrl-K and jumps to a certificate by any of its names', async () => {
  // M1: sans is `names[1:]` (the API never repeats the common name in it) —
  // 'cdn.example.net' is the one additional SAN this certificate has.
  server.use(...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com', sans: ['cdn.example.net'] })));
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  await user.type(await screen.findByPlaceholderText('www.example.com'), 'cdn.example');
  await user.click(await screen.findByRole('option', { name: /^edge/ }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-7/overview'));
});

// Review fix: Certificates now render before Actions (a "Renew <name>" item
// used to come first in the DOM, so Enter on a matching name renewed
// instead of navigating). cmdk auto-highlights the first matching item.
it('selects the matching certificate on Enter instead of the Renew action below it', async () => {
  const renewed: string[] = [];
  server.use(
    // M1: no additional SANs here, so sans is empty (never [commonName]).
    ...certificateHandlers(makeCert({ id: 'c-9', name: 'edge', commonName: 'edge.example.com' })),
    http.post(url('/orgs/org-1/certificates/:id/renew'), ({ params }) => (renewed.push(params.id as string), new HttpResponse(null, { status: 202 }))),
  );
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  await user.type(await screen.findByPlaceholderText('www.example.com'), 'edge');
  await screen.findByRole('option', { name: /^edge/ });
  await user.keyboard('{Enter}');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-9/overview'));
  expect(renewed).toEqual([]);
});

// M3: cmdk's default filter also matches a CommandItem's own `value`
// (`cert:<id>`, `page:<label>`, `action:*`, `renew:<id>` — kept distinct so
// two entries never collide on cmdk's own value-based selection, per this
// file's header comment) — without `keywordFilter`, typing a fragment of
// that internal id, which a real certificate id/uuid could easily contain,
// would surface a match no visible label or keyword ever mentions.
it('never matches on an internal cert:/page:/action: value, only on visible keywords', async () => {
  server.use(...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com' })));
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  await user.type(await screen.findByPlaceholderText('www.example.com'), 'cert:c-7');
  expect(screen.queryByRole('option', { name: /^edge/ })).not.toBeInTheDocument();
  expect(screen.getByText('No match.')).toBeInTheDocument();
});

// Ruling A3 (fix round 1): under All orgs the palette must not fall back
// to `me.orgs[0]` for its org-bound queries/actions — a global admin who
// never picked an org must not be able to renew or create in one they
// didn't choose, and the org-scoped page entries (Issuers…) don't apply
// to a cross-org view either.
it('drops org-bound actions and pages under All orgs, and never requests the first org', async () => {
  let calledOrgCerts = false;
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }], [org, org2]))),
    http.get(url('/certificates'), () => HttpResponse.json({ items: [], nextCursor: null })),
    http.get(url('/orgs/:orgId/certificates'), () => {
      calledOrgCerts = true;
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  const { user } = renderRoute('/o/all/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await within(dialog).findByPlaceholderText('www.example.com');
  expect(within(dialog).queryByText('New certificate')).not.toBeInTheDocument();
  expect(within(dialog).queryByText(/^Renew /)).not.toBeInTheDocument();
  expect(within(dialog).queryByText(/^Issuers:/)).not.toBeInTheDocument();
  expect(within(dialog).getByRole('option', { name: 'Overview' })).toBeInTheDocument();
  expect(within(dialog).getByRole('option', { name: 'Certificates' })).toBeInTheDocument();
  expect(calledOrgCerts).toBe(false);
});

// M7: under All orgs there's no single org to request /orgs/{orgId}/clients
// against — the cross-org GET /clients listing (already used by the clients
// list's own All orgs view) covers search here, navigating read-only to the
// client's own org.
it('searches clients across every org under All orgs and navigates read-only', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }], [org, org2]))),
    http.get(url('/certificates'), () => HttpResponse.json({ items: [], nextCursor: null })),
    http.get(url('/clients'), () => HttpResponse.json({ items: [makeClient({ id: 'cl-9', orgId: org2.id, name: 'lab-agent', hostname: 'lab.lan' })], nextCursor: null })),
    http.get(url('/orgs/org-2/clients/cl-9'), () => HttpResponse.json(makeClient({ id: 'cl-9', orgId: org2.id, name: 'lab-agent' }))),
    http.get(url('/orgs/org-2/clients/cl-9/grants'), () => HttpResponse.json({ items: [] })),
  );
  const { router, user } = renderRoute('/o/all/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await user.type(within(dialog).getByPlaceholderText('www.example.com'), 'lab-agent');
  await user.click(await within(dialog).findByRole('option', { name: /^lab-agent/ }));
  await waitFor(() => expect(router.state.location.pathname).toBe(`/o/${org2.slug}/clients/cl-9/certificates`));
});

// Fix round 2 (Important #1): a viewer can read certificates but has
// neither certs:write nor certs:issue — the Actions group's New
// certificate and Renew <name> entries must not appear, even with a
// matching search term.
it('hides New certificate and Renew for a viewer (no certs:write/certs:issue)', async () => {
  server.use(
    // First match wins within one server.use call, so this /auth/me
    // override must be listed before certificateHandlers' own (via
    // authHandlers).
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    ...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com' })),
  );
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await within(dialog).findByPlaceholderText('www.example.com');
  await user.type(within(dialog).getByPlaceholderText('www.example.com'), 'edge');
  await within(dialog).findByRole('option', { name: /^edge/ });
  expect(within(dialog).queryByText('New certificate')).not.toBeInTheDocument();
  expect(within(dialog).queryByText(/^Renew edge/)).not.toBeInTheDocument();
});

// Coordinator re-review: a caller with only certs:read in the current org
// (no cas:read/accounts:read/dnscreds:read/audit:read, no users:read
// anywhere) sees Certificates but none of the entries or actions gated on
// those other actions.
it('shows only certs:read-gated entries for a caller with only certs:read', async () => {
  permissionOverride = { can: (action) => action === 'certs:read', canAnywhere: () => false };
  server.use(...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com' })));
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await within(dialog).findByPlaceholderText('www.example.com');
  // The Certificates page entry itself (distinct from the "Certificates"
  // group heading above the matching certificate below), checked before
  // typing narrows the list to "edge" and would filter this page entry out.
  expect(within(dialog).getByRole('option', { name: 'Certificates' })).toBeInTheDocument();
  expect(within(dialog).queryByText('Audit log')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('Issuers: CAs')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('Issuers: ACME accounts')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('Issuers: DNS credentials')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('Settings: Access')).not.toBeInTheDocument();
  await user.type(within(dialog).getByPlaceholderText('www.example.com'), 'edge');
  await within(dialog).findByRole('option', { name: /^edge/ });
  expect(within(dialog).queryByText('New certificate')).not.toBeInTheDocument();
  expect(within(dialog).queryByText(/^Renew edge/)).not.toBeInTheDocument();
});

// Coordinator re-review: an org-admin (every org-scoped action, including
// audit:read/cas:read/accounts:read/dnscreds:read/users:read) sees every
// org-scoped page entry the viewer-only test above hides.
it('shows every org-scoped page entry for an org-admin', async () => {
  permissionOverride = { can: () => true, canAnywhere: () => true };
  server.use(...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com' })));
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await within(dialog).findByPlaceholderText('www.example.com');
  expect(within(dialog).getByText('Audit log')).toBeInTheDocument();
  expect(within(dialog).getByText('Issuers: CAs')).toBeInTheDocument();
  expect(within(dialog).getByText('Issuers: ACME accounts')).toBeInTheDocument();
  expect(within(dialog).getByText('Issuers: DNS credentials')).toBeInTheDocument();
  expect(within(dialog).getByText('Settings: Access')).toBeInTheDocument();
  expect(within(dialog).getByText('New certificate')).toBeInTheDocument();
});

// Task 2 (Phase 5B): the palette's own shortcut into the kind-aware CaSheet,
// pre-selecting Built-in CA (task-2-brief: same gating as "Issuers: CAs").
it('new private CA entry navigates to a new localca CA', async () => {
  server.use(...certificateHandlers(makeCert({ id: 'c-10', name: 'edge' })));
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await user.click(await within(dialog).findByText('Issuers: New private CA'));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/issuers/cas'));
  expect(router.state.location.search).toMatchObject({ edit: 'new', kind: 'localca' });
});

it('hides the new private CA entry without cas:read, same as Issuers: CAs', async () => {
  permissionOverride = { can: (a) => a !== 'cas:read', canAnywhere: () => true };
  server.use(...certificateHandlers(makeCert({ id: 'c-11', name: 'edge' })));
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await within(dialog).findByPlaceholderText('www.example.com');
  expect(within(dialog).queryByText('Issuers: New private CA')).not.toBeInTheDocument();
});

// Review fix: the palette's own dialog is exempt from the global suppress
// selector for Ctrl/Cmd-K specifically, so a second press — even with the
// search input focused — closes it instead of being swallowed the same way
// a generic dialog/sheet/popover swallows it (lib/shortcuts.test.ts).
it('closes on a second Ctrl-K pressed while its own search input has focus', async () => {
  server.use(...certificateHandlers(makeCert({ id: 'c-8', name: 'edge' })));
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const input = await screen.findByPlaceholderText('www.example.com');
  await user.click(input);
  expect(input).toHaveFocus();
  await user.keyboard('{Control>}k{/Control}');
  await waitFor(() => expect(screen.queryByPlaceholderText('www.example.com')).toBeNull());
});

it('jumps to a client by hostname and offers Enrol client to writers', async () => {
  server.use(
    ...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com' })),
    http.get(url('/orgs/org-1/clients'), () => HttpResponse.json({ items: [makeClient({ id: 'cl-4', name: 'db-1', hostname: 'db-1.rack-a.lan' })], nextCursor: null })),
    http.get(url('/orgs/org-1/clients/cl-4'), () => HttpResponse.json(makeClient({ id: 'cl-4', name: 'db-1' }))),
    http.get(url('/orgs/org-1/clients/cl-4/grants'), () => HttpResponse.json({ items: [] })),
  );
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  expect(await within(dialog).findByText('Enrol client')).toBeInTheDocument();
  expect(within(dialog).getByText('Delivery: File layouts')).toBeInTheDocument();
  expect(within(dialog).getByText('Settings: Agents')).toBeInTheDocument();
  await user.type(within(dialog).getByPlaceholderText('www.example.com'), 'rack-a');
  await user.click(await within(dialog).findByRole('option', { name: /^db-1/ }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/clients/cl-4/certificates'));
});

it('hides Enrol client and Delivery pages without the permissions', async () => {
  permissionOverride = { can: (a) => a === 'certs:read' || a === 'clients:read', canAnywhere: () => false };
  server.use(...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com' })));
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  expect(await within(dialog).findByText('Clients')).toBeInTheDocument();
  expect(within(dialog).queryByText('Enrol client')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('Delivery: Deploy targets')).not.toBeInTheDocument();
});

// Task 10: Import certificates and Upload certificate, next to New
// certificate, for the same canCreate writers (certs:write in the current
// org). Each is its own dedicated route, not filtered behind a search term
// the way Renew <name> is.
it('offers Import certificates and Upload certificate to writers, each navigating to its own route', async () => {
  server.use(...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com' })));
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });

  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await user.click(await within(dialog).findByText('Import certificates'));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/import'));

  await user.keyboard('{Control>}k{/Control}');
  const dialog2 = await screen.findByRole('dialog');
  await user.click(await within(dialog2).findByText('Upload certificate'));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/upload'));
});

it('hides Import certificates and Upload certificate for a viewer', async () => {
  server.use(
    // First match wins, so this /auth/me override must be listed before
    // certificateHandlers' own (via authHandlers).
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    ...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com' })),
  );
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await within(dialog).findByPlaceholderText('www.example.com');
  expect(within(dialog).queryByText('Import certificates')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('Upload certificate')).not.toBeInTheDocument();
});

it('settings integrations entry', async () => {
  server.use(...authHandlers({ authed: true }));
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await user.type(within(dialog).getByPlaceholderText('www.example.com'), 'openbao');
  await user.click(await within(dialog).findByText('Settings: Integrations'));
  await waitFor(() => expect(router.state.location.pathname).toBe('/settings/integrations'));
});

it('hides Import certificates and Upload certificate under All orgs', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }], [org, org2]))),
    http.get(url('/certificates'), () => HttpResponse.json({ items: [], nextCursor: null })),
  );
  const { user } = renderRoute('/o/all/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const dialog = await screen.findByRole('dialog');
  await within(dialog).findByPlaceholderText('www.example.com');
  expect(within(dialog).queryByText('Import certificates')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('Upload certificate')).not.toBeInTheDocument();
});
