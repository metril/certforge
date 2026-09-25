import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { adminUser, annUser, authHandlers, iso, makeApiKey, makeBinding, meWith, org, org2, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

const apiKey = makeApiKey();
const list = [
  makeBinding(),
  makeBinding({ id: 'rb-2', subjectType: 'oidc_group', subject: 'ops', subjectLabel: 'ops', role: 'operator', orgId: null }),
  makeBinding({ id: 'rb-9', subjectType: 'apikey', subject: apiKey.id, subjectLabel: apiKey.name, role: 'admin', orgId: org.id }),
];

function handlers(onPost?: (b: unknown) => Response | undefined) {
  return [
    http.get(url('/role-bindings'), () => HttpResponse.json({ items: list })),
    http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })),
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [apiKey] })),
    http.post(url('/role-bindings'), async ({ request }) => {
      const body = await request.json();
      return onPost?.(body) ?? HttpResponse.json(makeBinding({ id: 'rb-3' }), { status: 201 });
    }),
  ];
}

// Desktop by default (D5 mobile-card test overrides this), mirroring
// UsersTab's users.test.tsx viewport stub.
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}
const ORIGINAL_INNER_WIDTH = window.innerWidth;
beforeEach(() => {
  stubViewport(true);
});
afterEach(() => {
  vi.unstubAllGlobals();
  window.innerWidth = ORIGINAL_INNER_WIDTH;
});

it('lists bindings with subject, role and scope', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/access?tab=bindings');
  const table = await screen.findByRole('table', { name: 'Role bindings' });
  expect(await within(table).findByText('Ann')).toBeInTheDocument();
  // Fix round 1 (review): the user subject shows its looked-up email too.
  expect(within(table).getByText('ann@example.com')).toBeInTheDocument();
  expect(within(table).getAllByText('Acme').length).toBeGreaterThan(0);
  expect(within(table).getByText('ops')).toBeInTheDocument();
  expect(within(table).getByText('All orgs')).toBeInTheDocument();
  // The apikey subject shows the key's name plus its raw id in mono.
  expect(within(table).getByText(apiKey.name)).toBeInTheDocument();
  expect(within(table).getByText(apiKey.id)).toBeInTheDocument();
});

// Fix round 1 (review): a subject id that doesn't resolve (user/key not in
// the looked-up list) falls back to the raw id in mono instead of crashing
// or showing nothing.
it('falls back to the raw subject id when it cannot be resolved', async () => {
  const orphan = makeBinding({ id: 'rb-orphan', subject: 'u-missing', subjectLabel: 'u-missing' });
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/role-bindings'), () => HttpResponse.json({ items: [orphan] })),
    http.get(url('/users'), () => HttpResponse.json({ items: [adminUser] })),
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [] })),
  );
  renderRoute('/settings/access?tab=bindings');
  const table = await screen.findByRole('table', { name: 'Role bindings' });
  expect(await within(table).findByText('u-missing')).toBeInTheDocument();
});

it('adds a group binding', async () => {
  let body: unknown;
  server.use(...authHandlers({ authed: true }), ...handlers((b) => { body = b; return undefined; }));
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  await user.click(within(sheet).getByRole('radio', { name: 'Group' }));
  await user.type(within(sheet).getByLabelText('Group'), 'ops');
  await user.click(within(sheet).getByRole('radio', { name: 'Operator' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(body).toEqual({ subjectType: 'oidc_group', subject: 'ops', role: 'operator', orgId: org.id }));
});

it('says so when the binding already exists', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers(() => problem(409, 'This binding already exists.', {}, 'Conflict')));
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  await user.click(within(sheet).getByRole('combobox', { name: 'User' }));
  await user.click(await screen.findByRole('option', { name: /Ann/ }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByRole('alert')).toHaveTextContent('This binding already exists.');
});

it('offers All orgs only to global binding writers', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))),
    ...handlers(),
  );
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  await user.click(within(sheet).getByRole('combobox', { name: 'Scope' }));
  expect(await screen.findByRole('option', { name: 'Acme' })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: 'All orgs' })).not.toBeInTheDocument();
});

// Controller ruling: oidc_group bindings always need GLOBAL bindings:write,
// so an org-admin (no global binding) sees the Group segment disabled with
// a tooltip rather than able to create a group mapping in their own org.
it('disables the Group subject type for an org-admin with no global binding', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))),
    ...handlers(),
  );
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  const group = within(sheet).getByRole('radio', { name: 'Group' });
  expect(group).toHaveAttribute('data-disabled');
  await user.hover(group);
  expect(await screen.findByText('Only a global admin can add group mappings.')).toBeInTheDocument();
});

it('removes a binding after typing the subject', async () => {
  let deleted = '';
  server.use(...authHandlers({ authed: true }), ...handlers(),
    http.delete(url('/role-bindings/:id'), ({ params }) => { deleted = String(params.id); return new HttpResponse(null, { status: 204 }); }));
  const { user } = renderRoute('/settings/access?tab=bindings');
  const table = await screen.findByRole('table', { name: 'Role bindings' });
  await user.click(await within(table).findByRole('button', { name: 'Remove Ann viewer' }));
  const dialog = await screen.findByRole('dialog');
  await user.type(within(dialog).getByRole('textbox'), 'Ann');
  await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(deleted).toBe('rb-1'));
});

// Controller ruling: deleting the last enabled global admin's binding
// returns 409; the confirm dialog shows the problem detail inline and
// stays open (ConfirmDestructive's default error handling), same contract
// as UsersTab's own last-admin 409 test.
it('shows a 409 inline and keeps the remove dialog open', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers(),
    http.delete(url('/role-bindings/:id'), () => problem(409, 'Cannot remove the last global admin.')));
  const { user } = renderRoute('/settings/access?tab=bindings');
  const table = await screen.findByRole('table', { name: 'Role bindings' });
  await user.click(await within(table).findByRole('button', { name: 'Remove Ann viewer' }));
  const dialog = await screen.findByRole('dialog');
  await user.type(within(dialog).getByRole('textbox'), 'Ann');
  await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('Cannot remove the last global admin.');
  expect(screen.getByRole('dialog')).toBeInTheDocument();
});

// D5: card rows below 768px, no horizontal overflow at 375px.
it('shows card rows instead of a table below 768px with no horizontal overflow', async () => {
  stubViewport(false);
  window.innerWidth = 375;
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { container } = renderRoute('/settings/access?tab=bindings');
  await screen.findByText('Ann');
  expect(screen.queryByRole('table')).toBeNull();
  expect(screen.getByText('ops')).toBeInTheDocument();
  expect(screen.getByText('ann@example.com')).toBeInTheDocument();
  const cardsRoot = screen.getByText('Ann').closest('.grid.gap-2')!.parentElement!;
  expect(cardsRoot.className).not.toMatch(/min-w-\[/);
  expect(container.querySelector('[class*="min-w-["]')).toBeNull();
  expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(window.innerWidth);
});

// D5: type and org filters are both URL-synced, independently and together.
it('filters bindings by subject type and org, synced to the URL', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user, router } = renderRoute('/settings/access?tab=bindings');
  await screen.findByRole('table', { name: 'Role bindings' });
  await user.click(screen.getByRole('radio', { name: 'Groups' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ type: 'oidc_group' }));
  await user.click(screen.getByRole('combobox', { name: 'Org' }));
  await user.click(await screen.findByRole('option', { name: 'Acme' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ type: 'oidc_group', orgId: org.id }));
});

// D5: `q` filters client-side and is synced to the URL, same contract as
// UsersTab's own search box.
it('filters bindings by a URL-synced search term', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user, router } = renderRoute('/settings/access?tab=bindings');
  const table = await screen.findByRole('table', { name: 'Role bindings' });
  await within(table).findByText('Ann');
  await user.type(screen.getByRole('textbox', { name: 'Search bindings' }), 'ops');
  await waitFor(() => expect(router.state.location.search).toMatchObject({ q: 'ops' }));
  await waitFor(() => expect(within(screen.getByRole('table', { name: 'Role bindings' })).queryByText('Ann')).toBeNull());
  expect(within(screen.getByRole('table', { name: 'Role bindings' })).getByText('ops')).toBeInTheDocument();
});

// M4: a filtered-empty result gets a Clear filters button.
it('clears the search with a Clear filters button in the filtered-empty state', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user, router } = renderRoute('/settings/access?tab=bindings');
  await screen.findByRole('table', { name: 'Role bindings' });
  await user.type(screen.getByRole('textbox', { name: 'Search bindings' }), 'nobody-matches-this');
  await waitFor(() => expect(router.state.location.search).toMatchObject({ q: 'nobody-matches-this' }));
  await user.click(await screen.findByRole('button', { name: 'Clear filters' }));
  await waitFor(() => expect(router.state.location.search).toEqual({ tab: 'bindings' }));
  expect(await screen.findByRole('table', { name: 'Role bindings' })).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Search bindings' })).toHaveValue('');
});

// Item 1's required test: the server actually receives the subject-type
// filter, not just the URL.
it('requests bindings filtered by subject type from the server', async () => {
  let lastQuery: URLSearchParams | undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/role-bindings'), ({ request }) => {
      lastQuery = new URL(request.url).searchParams;
      return HttpResponse.json({ items: list });
    }),
    http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })),
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [apiKey] })),
  );
  renderRoute('/settings/access?tab=bindings&type=oidc_group');
  await waitFor(() => expect(lastQuery?.get('subjectType')).toBe('oidc_group'));
});

// Controller ruling (item 3, fix round 1): the API key picker only offers
// keys the caller may actually bind — apikeys:write at the key's own scope —
// and excludes expired and revoked keys.
it('filters the API key picker to keys the caller may bind, excluding expired and revoked ones', async () => {
  const bindable = makeApiKey({ id: 'k-ok', name: 'ok-key', orgId: org.id });
  const otherOrg = makeApiKey({ id: 'k-other', name: 'other-org-key', orgId: org2.id });
  const expired = makeApiKey({ id: 'k-expired', name: 'expired-key', orgId: org.id, expiresAt: iso(-1) });
  const revoked = makeApiKey({ id: 'k-revoked', name: 'revoked-key', orgId: org.id, revokedAt: iso(-1) });
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))),
    http.get(url('/role-bindings'), () => HttpResponse.json({ items: list })),
    http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })),
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [bindable, otherOrg, expired, revoked] })),
  );
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  await user.click(within(sheet).getByRole('radio', { name: 'API key' }));
  await user.click(within(sheet).getByRole('combobox', { name: 'API key' }));
  expect(await screen.findByRole('option', { name: /ok-key/ })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: /other-org-key/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('option', { name: /expired-key/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('option', { name: /revoked-key/ })).not.toBeInTheDocument();
});
