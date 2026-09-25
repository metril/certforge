import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeCert, meWith, org, org2, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

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
