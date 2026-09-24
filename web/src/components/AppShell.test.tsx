import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

function viewport(wide: boolean) {
  vi.stubGlobal('matchMedia', (q: string) => ({
    matches: wide && q.includes('min-width: 1280px'),
    media: q,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}
afterEach(() => vi.unstubAllGlobals());

it('shows eight items; Phase 1 items link, the rest are disabled with a tooltip', async () => {
  viewport(true);
  server.use(...authHandlers({ authed: true }));
  renderRoute('/o/acme/certificates');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  const links: [string, string][] = [
    ['Overview', '/o/acme/overview'],
    ['Certificates', '/o/acme/certificates'],
    ['Issuers', '/o/acme/issuers'],
    ['Settings', '/settings/general'],
  ];
  for (const [name, href] of links) expect(within(nav).getByRole('link', { name })).toHaveAttribute('href', href);
  expect(within(nav).getByRole('link', { name: 'Certificates' })).toHaveAttribute('aria-current', 'page');
  for (const name of ['Clients', 'Delivery', 'Alerts', 'Audit log']) {
    expect(within(nav).getByText(name).closest('[aria-disabled="true"]')).not.toBeNull();
  }
  expect(within(nav).getByText('Operate')).toBeInTheDocument();
  act(() => (within(nav).getByText('Clients').closest('[aria-disabled="true"]') as HTMLElement).focus());
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Available in a later phase');
});

it('renders an icon rail with accessible names below 1280 px', async () => {
  viewport(false);
  server.use(...authHandlers({ authed: true }));
  renderRoute('/o/acme/overview');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  expect(within(nav).getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
  expect(within(nav).queryByText('Operate')).toBeNull();
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
