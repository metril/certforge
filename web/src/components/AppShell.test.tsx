import { act, screen, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { afterEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, me, org, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// A controllable `matchMedia` mock: each query string gets its own
// listener set, so `set(query, matches)` can simulate a live viewport
// change (a real `change` event), not just the value read at mount.
function stubMatchMedia(initial: Record<string, boolean>) {
  const state = { ...initial };
  const listeners = new Map<string, Set<() => void>>();
  vi.stubGlobal('matchMedia', (query: string) => ({
    get matches() {
      return state[query] ?? false;
    },
    media: query,
    addEventListener: (_type: string, cb: () => void) => {
      let set = listeners.get(query);
      if (!set) listeners.set(query, (set = new Set()));
      set.add(cb);
    },
    removeEventListener: (_type: string, cb: () => void) => {
      listeners.get(query)?.delete(cb);
    },
  }));
  return {
    set(query: string, matches: boolean) {
      state[query] = matches;
      listeners.get(query)?.forEach((cb) => cb());
    },
  };
}

// `min768` defaults to true (tablet: icon rail, aside visible) so the
// existing "not wide" tests keep meaning "narrower than 1280 px" without
// also implying phone/drawer mode; pass `false` explicitly for that.
function viewport(min1280: boolean, min768 = true) {
  return stubMatchMedia({ '(min-width: 1280px)': min1280, '(min-width: 768px)': min1280 || min768 });
}

afterEach(() => vi.unstubAllGlobals());

it('shows eight items; enabled items link, the rest are disabled with a tooltip', async () => {
  viewport(true);
  server.use(...authHandlers({ authed: true }));
  renderRoute('/o/acme/certificates');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  const links: [string, string][] = [
    ['Overview', '/o/acme/overview'],
    ['Certificates', '/o/acme/certificates'],
    ['Clients', '/o/acme/clients'],
    ['Delivery', '/o/acme/delivery'],
    ['Alerts', '/o/acme/alerts/channels'],
    ['Issuers', '/o/acme/issuers'],
    ['Audit log', '/o/acme/audit'],
    ['Settings', '/settings/general'],
  ];
  for (const [name, href] of links) expect(within(nav).getByRole('link', { name })).toHaveAttribute('href', href);
  expect(within(nav).getByRole('link', { name: 'Certificates' })).toHaveAttribute('aria-current', 'page');
  expect(within(nav).getByText('Operate')).toBeInTheDocument();
});

// 6B Task 2: Alerts moved from the disabled LATER row to a real link.
it('alerts nav links to channels', async () => {
  viewport(true);
  server.use(...authHandlers({ authed: true }));
  renderRoute('/o/acme/certificates');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  expect(within(nav).getByRole('link', { name: 'Alerts' })).toHaveAttribute('href', '/o/acme/alerts/channels');
});

it('renders an icon rail with accessible names below 1280 px', async () => {
  viewport(false);
  server.use(...authHandlers({ authed: true }));
  renderRoute('/o/acme/overview');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  expect(within(nav).getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
  expect(within(nav).queryByText('Operate')).toBeNull();
});

// Re-review fix: TargetLink (the icon rail's <Link>) forwarded a ref
// (fixed in the Critical commit) but still destructured only its own named
// props, dropping the onPointerMove/onFocus/onBlur Radix's Slot merges
// onto whatever `TooltipTrigger asChild` clones — without them reaching the
// actual <a>, Radix never sees the hover that should open the tooltip.
it('opens a tooltip on hover for a compact icon-rail link', async () => {
  viewport(false);
  server.use(...authHandlers({ authed: true }));
  const { user } = renderRoute('/o/acme/overview');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  await user.hover(within(nav).getByRole('link', { name: 'Certificates' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Certificates');
});

it('signs out from the user menu', async () => {
  viewport(true);
  server.use(...authHandlers({ authed: true }));
  const { router, user } = renderRoute('/o/acme/overview');
  await user.click(await screen.findByRole('button', { name: 'Account menu for admin' }));
  expect(screen.getByRole('radio', { name: 'Dark' })).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Sign out' }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
});

it('highlights Settings on any section, not just the one the link resolves to', async () => {
  viewport(true);
  server.use(
    ...authHandlers({ authed: true }),
    // The Sidebar's own Settings link resolves to /settings/general
    // (Sidebar.tsx); /settings/backup proves isNavPathActive's prefix
    // match, not an exact-href match. Backup's own content needs these two.
    http.get(url('/settings/backup'), () => HttpResponse.json({ schema: { type: 'object', properties: {} }, value: {}, stored: null })),
    http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok' } })),
  );
  renderRoute('/settings/backup');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  expect(within(nav).getByRole('link', { name: 'Settings' })).toHaveAttribute('aria-current', 'page');
});

it('closes the drawer when the route changes, even without the nav link callback', async () => {
  viewport(false, false);
  server.use(...authHandlers({ authed: true }));
  const { router, user } = renderRoute('/o/acme/overview');
  await user.click(await screen.findByRole('button', { name: 'Open navigation' }));
  await screen.findByRole('dialog');
  await router.navigate({ to: '/o/$org/certificates', params: { org: 'acme' } });
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
});

it('closes the drawer when the viewport widens past the drawer breakpoint', async () => {
  const mq = viewport(false, false);
  server.use(...authHandlers({ authed: true }));
  const { user } = renderRoute('/o/acme/overview');
  await user.click(await screen.findByRole('button', { name: 'Open navigation' }));
  await screen.findByRole('dialog');
  act(() => mq.set('(min-width: 768px)', true));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
});

it('disables org-scoped nav and lands on a no-organization empty state when the account has no orgs', async () => {
  viewport(true);
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json({ ...me, orgs: [] })),
  );
  renderRoute('/no-organization');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  for (const name of ['Overview', 'Certificates', 'Issuers']) {
    expect(within(nav).getByText(name).closest('[aria-disabled="true"]')).not.toBeNull();
  }
  expect(within(nav).getByRole('link', { name: 'Settings' })).toBeInTheDocument();
  expect(await screen.findByText(/no organization/i)).toBeInTheDocument();
});

it('lists every org in the switcher, with the active org named in the trigger, once there is more than one', async () => {
  viewport(true);
  const orgs = [org, { id: 'org-2', slug: 'other', name: 'Other Co' }];
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json({ ...me, orgs })),
  );
  const { user } = renderRoute('/o/acme/overview');
  const trigger = await screen.findByRole('button', { name: 'Organization: Acme' });
  await user.click(trigger);
  expect(screen.getByRole('menuitem', { name: 'Acme' })).toBeInTheDocument();
  expect(screen.getByRole('menuitem', { name: 'Other Co' })).toBeInTheDocument();
});

it('puts the sidebar on its own darker surface and the content on the canvas', async () => {
  viewport(true);
  server.use(...authHandlers({ authed: true }));
  renderRoute('/o/acme/certificates');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  const aside = nav.closest('aside')!;
  expect(aside.className).toContain('bg-sidebar');
  expect(aside.className).toContain('border-r');
  expect(screen.getByRole('main').parentElement!.className).toContain('bg-surface');
  expect(screen.getByRole('main').parentElement!.className).not.toContain('bg-panel');
});
