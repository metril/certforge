import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, DAY, iso, makeApiKey, meWith, NOW, org, url } from '@/test/fixtures';
import { keyState } from '@/lib/apiKeys';
import { renderRoute } from '@/test/render';

// Roles cannot make a scope grantable globally but not in an org, so the
// prune test narrows one scope by hand.
const narrow = vi.hoisted(() => ({ on: false }));
vi.mock('@/lib/permissions', async (orig) => {
  const mod = await orig<typeof import('@/lib/permissions')>();
  return { ...mod, canGrantScope: (me: never, s: never, orgId: string | null) => (narrow.on && s === 'keys:export' ? orgId === null : mod.canGrantScope(me, s, orgId)) };
});

const TOKEN = 'cf_0123456789ab_' + 'x'.repeat(43);

function handlers(onPost?: (b: Record<string, unknown>) => void) {
  return [
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [makeApiKey(), makeApiKey({ id: 'k-2', name: 'old', revokedAt: iso(-1) })] })),
    http.post(url('/api-keys'), async ({ request }) => {
      const b = (await request.json()) as Record<string, unknown>;
      onPost?.(b);
      return HttpResponse.json({ apiKey: makeApiKey({ id: 'k-3', name: String(b.name) }), token: TOKEN }, { status: 201 });
    }),
  ];
}

// Desktop by default; the mobile-card test below overrides this, mirroring
// bindings.test.tsx / users.test.tsx.
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
  window.innerWidth = ORIGINAL_INNER_WIDTH;
});

it('computes key state', () => {
  expect(keyState(makeApiKey())).toBe('active');
  expect(keyState(makeApiKey({ expiresAt: iso(-1) }))).toBe('expired');
  expect(keyState(makeApiKey({ revokedAt: iso(-1) }))).toBe('revoked');
});

it('creates a key and shows the secret dialog until acknowledged', async () => {
  // Pin the clock (no auto-advance) so the 30-day preset's ISO instant can
  // be asserted exactly, not just "is a string" (fix round 1 item 2).
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  let body: Record<string, unknown> = {};
  server.use(...authHandlers({ authed: true }), ...handlers((b) => (body = b)));
  const { user, queryClient } = renderRoute('/settings/access?tab=keys');
  const table = await screen.findByRole('table', { name: 'API keys' });
  expect(await within(table).findByText('Revoked')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'New API key' }));
  const sheet = await screen.findByRole('dialog', { name: 'New API key' });
  await user.type(within(sheet).getByLabelText('Name'), 'deploy');
  await user.click(within(sheet).getByRole('button', { name: 'certs:issue' }));
  await user.click(within(sheet).getByRole('radio', { name: '30 days' }));
  await user.click(within(sheet).getByRole('button', { name: 'Create' }));
  await waitFor(() => expect(body.name).toBe('deploy'));
  expect(body.scopes).toEqual(['certs:read', 'certs:issue']);
  expect(body.orgId).toBe(org.id);
  expect(body.expiresAt).toBe(new Date(NOW + 30 * DAY).toISOString());

  const dialog = await screen.findByRole('dialog', { name: 'API key deploy' });
  expect(within(dialog).getByText(TOKEN)).toBeInTheDocument();
  await user.keyboard('{Escape}');
  expect(screen.getByRole('dialog', { name: 'API key deploy' })).toBeInTheDocument();
  const done = within(dialog).getByRole('button', { name: 'Done' });
  expect(done).toBeDisabled();
  await user.click(within(dialog).getByRole('switch', { name: 'Stored safely' }));
  await user.click(done);
  expect(screen.queryByText(TOKEN)).not.toBeInTheDocument();
  const cached = queryClient.getMutationCache().getAll().map((m) => JSON.stringify(m.state.data ?? null));
  expect(cached.some((s) => s.includes(TOKEN))).toBe(false);
});

// Fix round 1 item 1: a custom expiry reveals a date field, sends the end
// of that local day as an ISO instant, and rejects a past date inline.
it('sends a custom expiry as end-of-day local time and rejects a past date', async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  let body: Record<string, unknown> = {};
  server.use(...authHandlers({ authed: true }), ...handlers((b) => (body = b)));
  const { user } = renderRoute('/settings/access?tab=keys');
  await user.click(await screen.findByRole('button', { name: 'New API key' }));
  const sheet = await screen.findByRole('dialog', { name: 'New API key' });
  await user.type(within(sheet).getByLabelText('Name'), 'deploy');
  await user.click(within(sheet).getByRole('radio', { name: 'Custom' }));
  const date = within(sheet).getByLabelText('Expiry date');
  const create = within(sheet).getByRole('button', { name: 'Create' });

  // A past date is rejected inline and blocks submission.
  await user.type(date, '2020-01-01');
  expect(within(sheet).getByRole('alert')).toHaveTextContent(/hasn't passed/);
  expect(create).toBeDisabled();

  // A future date sends the end of that local day as an ISO instant.
  await user.clear(date);
  await user.type(date, '2026-12-31');
  expect(create).toBeEnabled();
  await user.click(create);
  await waitFor(() => expect(body.name).toBe('deploy'));
  expect(body.expiresAt).toBe(new Date(2026, 11, 31, 23, 59, 59, 999).toISOString());
});

it('disables scopes the role cannot grant', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))),
    ...handlers(),
  );
  const { user } = renderRoute('/settings/access?tab=keys');
  await user.click(await screen.findByRole('button', { name: 'New API key' }));
  const sheet = await screen.findByRole('dialog', { name: 'New API key' });
  expect(within(sheet).getByRole('button', { name: 'admin' })).toBeDisabled();
  expect(within(sheet).getByRole('button', { name: 'keys:export' })).toBeDisabled();
  expect(within(sheet).getByRole('button', { name: 'certs:write' })).toBeEnabled();
});

it('revokes after typing the key name', async () => {
  let revoked = '';
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers(),
    http.delete(url('/api-keys/:id'), ({ params }) => {
      revoked = String(params.id);
      return new HttpResponse(null, { status: 204 });
    }),
  );
  const { user } = renderRoute('/settings/access?tab=keys');
  const table = await screen.findByRole('table', { name: 'API keys' });
  await user.click(await within(table).findByRole('button', { name: 'Revoke ci' }));
  const dialog = await screen.findByRole('dialog', { name: 'Revoke ci' });
  await user.type(within(dialog).getByRole('textbox'), 'ci');
  await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));
  await waitFor(() => expect(revoked).toBe('k-1'));
});

// A revoked or expired key shows a status chip and no Revoke action
// (controller ruling).
it('hides the Revoke action for a revoked key', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user } = renderRoute('/settings/access?tab=keys');
  const table = await screen.findByRole('table', { name: 'API keys' });
  await within(table).findByText('old');
  expect(within(table).queryByRole('button', { name: 'Revoke old' })).not.toBeInTheDocument();
  await user.click(await within(table).findByRole('button', { name: 'Revoke ci' }));
  expect(await screen.findByRole('dialog', { name: 'Revoke ci' })).toBeInTheDocument();
});

// An expired (not revoked) key also shows a status chip and no Revoke
// action (fix round 1 item 4).
it('shows the Expired chip and hides Revoke for an expired key', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [makeApiKey({ id: 'k-4', name: 'stale', expiresAt: iso(-1) })] })),
  );
  renderRoute('/settings/access?tab=keys');
  const table = await screen.findByRole('table', { name: 'API keys' });
  await within(table).findByText('stale');
  expect(within(table).getByText('Expired')).toBeInTheDocument();
  expect(within(table).queryByRole('button', { name: 'Revoke stale' })).not.toBeInTheDocument();
});

// D4/D5: the mobile card view renders the same expired state.
it('shows the Expired chip and hides Revoke in the mobile card view', async () => {
  stubViewport(false);
  window.innerWidth = 375;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [makeApiKey({ id: 'k-4', name: 'stale', expiresAt: iso(-1) })] })),
  );
  renderRoute('/settings/access?tab=keys');
  const name = await screen.findByText('stale');
  const card = name.closest<HTMLElement>('.grid.gap-2')!;
  expect(within(card).getByText('Expired')).toBeInTheDocument();
  expect(within(card).queryByRole('button', { name: 'Revoke stale' })).not.toBeInTheDocument();
});

// 404/403 on revoke shows the problem detail inline instead of throwing.
it('shows a 403 inline and keeps the revoke dialog open', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers(),
    http.delete(url('/api-keys/:id'), () =>
      HttpResponse.json({ type: 'about:blank', title: 'Forbidden', status: 403, detail: 'Not your key to revoke.' }, { status: 403, headers: { 'Content-Type': 'application/problem+json' } }),
    ),
  );
  const { user } = renderRoute('/settings/access?tab=keys');
  const table = await screen.findByRole('table', { name: 'API keys' });
  await user.click(await within(table).findByRole('button', { name: 'Revoke ci' }));
  const dialog = await screen.findByRole('dialog', { name: 'Revoke ci' });
  await user.type(within(dialog).getByRole('textbox'), 'ci');
  await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('Not your key to revoke.');
  expect(screen.getByRole('dialog', { name: 'Revoke ci' })).toBeInTheDocument();
});

// D5: URL-synced state filter.
it('filters keys by state, synced to the URL', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user, router } = renderRoute('/settings/access?tab=keys');
  const table = await screen.findByRole('table', { name: 'API keys' });
  await within(table).findByText('ci');
  await user.click(screen.getByRole('radio', { name: 'Revoked' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ state: 'revoked' }));
  await waitFor(() => expect(within(screen.getByRole('table', { name: 'API keys' })).queryByText('ci')).toBeNull());
  expect(within(screen.getByRole('table', { name: 'API keys' })).getByText('old')).toBeInTheDocument();
});

// D5: a filtered-to-empty result offers a way back instead of a dead end.
it('clears filters from the empty state', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user, router } = renderRoute('/settings/access?tab=keys&q=nope');
  await waitFor(() => expect(router.state.location.search).toMatchObject({ q: 'nope' }));
  await user.click(await screen.findByRole('button', { name: 'Clear filters' }));
  await waitFor(() => expect(router.state.location.search.q).toBeUndefined());
  expect(await screen.findByRole('table', { name: 'API keys' })).toBeInTheDocument();
});

// D5: saved views for the API keys tab.
it('offers saved views for the API keys tab', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/access?tab=keys');
  await screen.findByRole('table', { name: 'API keys' });
  expect(screen.getByRole('button', { name: /save view/i })).toBeInTheDocument();
});

// D5: card rows below 768px, no horizontal overflow at 375px.
it('shows card rows instead of a table below 768px with no horizontal overflow', async () => {
  stubViewport(false);
  window.innerWidth = 375;
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { container } = renderRoute('/settings/access?tab=keys');
  await screen.findByText('ci');
  expect(screen.queryByRole('table')).toBeNull();
  expect(screen.getByText('old')).toBeInTheDocument();
  const cardsRoot = screen.getByText('ci').closest('.grid.gap-2')!.parentElement!;
  expect(cardsRoot.className).not.toMatch(/min-w-\[/);
  expect(container.querySelector('[class*="min-w-["]')).toBeNull();
  expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(window.innerWidth);
});

// H2: under a server maximum lifetime the sheet drops "Never", offers only
// choices that fit, defaults to the maximum and caps the custom date.
it('limits expiry choices to the server policy and defaults to the maximum', async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  let body: Record<string, unknown> = {};
  server.use(
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [], policy: { maxLifetimeDays: 45, maxActivePerUser: 50 } })),
    ...authHandlers({ authed: true }),
    ...handlers((b) => (body = b)),
  );
  const { user } = renderRoute('/settings/access?tab=keys');
  await user.click(await screen.findByRole('button', { name: 'New API key' }));
  const sheet = await screen.findByRole('dialog', { name: 'New API key' });
  expect(await within(sheet).findByRole('radio', { name: '45 days' })).toBeChecked();
  expect(within(sheet).getByRole('radio', { name: '30 days' })).toBeInTheDocument();
  expect(within(sheet).queryByRole('radio', { name: '90 days' })).not.toBeInTheDocument();
  expect(within(sheet).queryByRole('radio', { name: 'Never' })).not.toBeInTheDocument();
  expect(within(sheet).getByText(/at most 45 days/)).toBeInTheDocument();

  await user.click(within(sheet).getByRole('radio', { name: 'Custom' }));
  await user.type(within(sheet).getByLabelText('Expiry date'), '2027-12-31');
  expect(within(sheet).getByRole('alert')).toHaveTextContent('Pick a date within 45 days.');
  expect(within(sheet).getByRole('button', { name: 'Create' })).toBeDisabled();

  await user.click(within(sheet).getByRole('radio', { name: '45 days' }));
  await user.type(within(sheet).getByLabelText('Name'), 'deploy');
  await user.click(within(sheet).getByRole('button', { name: 'Create' }));
  await waitFor(() => expect(body.name).toBe('deploy'));
  expect(body.expiresAt).toBe(new Date(NOW + 45 * DAY).toISOString());
});

// X11: a scope change drops permissions it makes ungrantable, from the chips and the request.
it('drops a picked permission that the new scope cannot grant', async () => {
  narrow.on = true;
  let body: Record<string, unknown> = {};
  server.use(...authHandlers({ authed: true }), ...handlers((b) => (body = b)));
  const { user } = renderRoute('/settings/access?tab=keys');
  await user.click(await screen.findByRole('button', { name: 'New API key' }));
  const sheet = await screen.findByRole('dialog', { name: 'New API key' });
  await user.type(within(sheet).getByLabelText('Name'), 'deploy');
  await user.click(within(sheet).getByRole('combobox', { name: 'Scope' }));
  await user.click(await screen.findByRole('option', { name: 'All orgs' }));
  const chip = within(sheet).getByRole('button', { name: 'keys:export' });
  await user.click(chip);
  expect(chip).toHaveAttribute('aria-pressed', 'true');
  await user.click(within(sheet).getByRole('combobox', { name: 'Scope' }));
  await user.click(await screen.findByRole('option', { name: 'Acme' }));
  expect(within(sheet).getByRole('button', { name: 'keys:export' })).toHaveAttribute('aria-pressed', 'false');
  await user.click(within(sheet).getByRole('button', { name: 'Create' }));
  await waitFor(() => expect(body.name).toBe('deploy'));
  expect(body.scopes).toEqual(['certs:read']);
  narrow.on = false;
});

// X12: the one-time key survives a route change until it is marked stored.
it('blocks a route change while the new key is unacknowledged', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user, router } = renderRoute('/settings/access?tab=keys');
  await user.click(await screen.findByRole('button', { name: 'New API key' }));
  const sheet = await screen.findByRole('dialog', { name: 'New API key' });
  await user.type(within(sheet).getByLabelText('Name'), 'deploy');
  await user.click(within(sheet).getByRole('button', { name: 'Create' }));
  const dialog = await screen.findByRole('dialog', { name: 'API key deploy' });
  void router.navigate({ to: '/o/$org/audit', params: { org: 'acme' } });
  await new Promise((r) => setTimeout(r, 50));
  expect(router.state.location.pathname).toBe('/settings/access');
  await user.click(within(dialog).getByRole('switch', { name: 'Stored safely' }));
  void router.navigate({ to: '/o/$org/audit', params: { org: 'acme' } });
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/audit'));
});
