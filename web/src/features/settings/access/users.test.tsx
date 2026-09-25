import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { adminUser, annUser, authHandlers, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { onTabChange } from './AccessPage';

// A controllable `matchMedia` mock, matching CertificatesPage's own
// list.test.tsx convention: only the `(min-width: 768px)` query (the one
// UsersTab checks for card rows, controller ruling D5) is meaningful here.
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

const ORIGINAL_INNER_WIDTH = window.innerWidth;

// Desktop by default so the table-oriented assertions below hold; the
// card-rows test overrides this with stubViewport(false).
beforeEach(() => {
  stubViewport(true);
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.innerWidth = ORIGINAL_INNER_WIDTH;
});

it('lists users and disables one after typing their name', async () => {
  let patched: unknown = null;
  let users = [adminUser, annUser];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/users'), () => HttpResponse.json({ items: users })),
    http.patch(url('/users/:id'), async ({ request, params }) => {
      patched = await request.json();
      users = users.map((u) => (u.id === params.id ? { ...u, disabled: true } : u));
      return HttpResponse.json(users.find((u) => u.id === params.id));
    }),
  );
  const { user } = renderRoute('/settings/access');
  const table = await screen.findByRole('table', { name: 'Users' });
  expect(within(table).getByText('Local admin')).toBeInTheDocument();
  expect(within(table).getByText('login.example.com')).toBeInTheDocument();
  expect(within(table).getByRole('switch', { name: 'admin active' })).toBeDisabled();
  await user.click(within(table).getByRole('switch', { name: 'Ann active' }));
  const dialog = await screen.findByRole('dialog', { name: 'Disable Ann' });
  await user.type(within(dialog).getByRole('textbox'), 'Ann');
  await user.click(within(dialog).getByRole('button', { name: 'Disable' }));
  // C3: assertions on MSW-captured request bodies after a click go through waitFor.
  await waitFor(() => expect(patched).toEqual({ disabled: true }));
  expect(await within(table).findByText('Disabled')).toBeInTheDocument();
});

it('keeps the tab in the URL', async () => {
  server.use(...authHandlers({ authed: true }), http.get(url('/users'), () => HttpResponse.json({ items: [adminUser] })));
  const { router } = renderRoute('/settings/access?tab=users');
  await screen.findByRole('tab', { name: 'Users', selected: true });
  expect(router.state.location.search).toEqual({ tab: 'users' });
});

it('falls back to the Users tab for an unrecognized ?tab value', async () => {
  server.use(...authHandlers({ authed: true }), http.get(url('/users'), () => HttpResponse.json({ items: [adminUser] })));
  renderRoute('/settings/access?tab=bogus');
  await screen.findByRole('tab', { name: 'Users', selected: true });
});

// D5/controller ruling: `q` is a per-tab filter, so switching tabs drops it.
// Only one tab exists yet (Tasks 4/6 add Role bindings and API keys) and
// Radix Tabs' controlled `onValueChange` only fires when the clicked trigger
// differs from the current value (@radix-ui/react-use-controllable-state
// bails out with `value2 !== prop`), so this can't be driven by clicking the
// sole existing tab. `onTabChange` is exported from AccessPage specifically
// so this merge logic is unit-testable without that constraint.
it('drops the search term when switching tabs', () => {
  expect(onTabChange({ tab: 'users', q: 'ann' }, 'users')).toEqual({ tab: 'users', q: undefined });
  expect(onTabChange({ q: 'ann', type: 'user' }, 'bindings')).toEqual({ q: undefined, type: 'user', tab: 'bindings' });
});

it('shows switches read-only without users:write', async () => {
  const orgAdmin = meWith([{ role: 'org-admin', orgId: org.id }]);
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(orgAdmin)),
    http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })),
  );
  renderRoute('/settings/access');
  const table = await screen.findByRole('table', { name: 'Users' });
  expect(within(table).getByRole('switch', { name: 'Ann active' })).toBeDisabled();
});

// Controller ruling: a 409 (self-disable or last admin) shows the problem
// detail inline next to the row and the switch reverts. There's no
// optimistic update here (the switch only reflects a *successful* PATCH), so
// "reverts" means the switch simply never changes and the dialog stays open
// with the server's detail instead of closing as if it had gone through.
it('shows a 409 inline and leaves the switch untouched', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })),
    http.patch(url('/users/:id'), () => problem(409, 'Cannot disable the last global admin.')),
  );
  const { user } = renderRoute('/settings/access');
  const table = await screen.findByRole('table', { name: 'Users' });
  await user.click(within(table).getByRole('switch', { name: 'Ann active' }));
  const dialog = await screen.findByRole('dialog', { name: 'Disable Ann' });
  await user.type(within(dialog).getByRole('textbox'), 'Ann');
  await user.click(within(dialog).getByRole('button', { name: 'Disable' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('Cannot disable the last global admin.');
  // Dialog stayed open (didn't close as if the PATCH had succeeded), and the
  // row's switch never flipped. Radix marks the rest of the page
  // aria-hidden while the dialog is open, so the switch is queried with
  // `hidden: true` rather than by its (currently inert) accessible role.
  expect(screen.getByRole('dialog', { name: 'Disable Ann' })).toBeInTheDocument();
  expect(within(table).getByRole('switch', { name: 'Ann active', hidden: true })).toBeChecked();
});

it("locks the current user's own switch with a tooltip", async () => {
  server.use(...authHandlers({ authed: true }), http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })));
  const { user } = renderRoute('/settings/access');
  const table = await screen.findByRole('table', { name: 'Users' });
  const self = within(table).getByRole('switch', { name: 'admin active' });
  expect(self).toBeDisabled();
  await user.hover(self);
  expect(await screen.findByText("You can’t disable your own account.")).toBeInTheDocument();
});

// D5: card rows below `md`, and no horizontal overflow of either the list
// container or the document at 375px. jsdom has no layout engine (see
// NamesStep.test.tsx's own note on this), so the automatable proxy is: no
// table renders, the card list uses a wrapping/stacking layout with no
// min-width utility that would force a wider viewport, and the document's
// reported scrollWidth stays within the 375px stub window.
it('shows card rows instead of a table below 768px with no horizontal overflow', async () => {
  stubViewport(false);
  window.innerWidth = 375;
  server.use(...authHandlers({ authed: true }), http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })));
  const { container } = renderRoute('/settings/access');
  await screen.findByText('Ann');
  expect(screen.queryByRole('table')).toBeNull();
  // Important (review fix round 1): the card row shows the user's email too,
  // not just name/source/groups.
  expect(screen.getByText('ann@example.com')).toBeInTheDocument();
  const list = screen.getByText('Ann').closest('.grid.gap-2')!.parentElement!;
  expect(list.className).not.toMatch(/min-w-\[/);
  expect(container.querySelector('[class*="min-w-["]')).toBeNull();
  expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(window.innerWidth);
});

// D5: `q` filters the list and is synced to the URL.
it('filters users by a URL-synced search term', async () => {
  server.use(...authHandlers({ authed: true }), http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })));
  const { user, router } = renderRoute('/settings/access');
  const table = await screen.findByRole('table', { name: 'Users' });
  expect(within(table).getByText('Ann')).toBeInTheDocument();
  await user.type(screen.getByRole('textbox', { name: 'Search users' }), 'admin');
  await waitFor(() => expect(router.state.location.search).toMatchObject({ q: 'admin' }));
  await waitFor(() => expect(within(screen.getByRole('table', { name: 'Users' })).queryByText('Ann')).toBeNull());
  expect(within(screen.getByRole('table', { name: 'Users' })).getByText('admin')).toBeInTheDocument();
});
