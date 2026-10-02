import { http, HttpResponse } from 'msw';
import { screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

it('shows a degraded vault check while the server is ready', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok', vault: 'degraded' } })),
  );
  renderRoute('/o/acme/overview');
  const strip = await screen.findByRole('alert', { name: 'Server health' });
  expect(within(strip).getByText('vault: degraded')).toBeInTheDocument();
  expect(within(strip).queryByText('Server not ready')).not.toBeInTheDocument();
  expect(within(strip).getByRole('link', { name: 'Integrations' })).toHaveAttribute('href', '/settings/integrations');
});

it('backup degraded links to backups', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok', backup: 'degraded' } })),
  );
  renderRoute('/o/acme/overview');
  const strip = await screen.findByRole('alert', { name: 'Server health' });
  expect(within(strip).getByText('backup: degraded')).toBeInTheDocument();
  expect(within(strip).getByRole('link', { name: 'Backups' })).toHaveAttribute('href', '/settings/backup');
});

it('degraded not listed as failing', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get('*/readyz', () => HttpResponse.json({ status: 'unavailable', checks: { database: 'ok', kek: 'failed', vault: 'degraded' } }, { status: 503 })),
  );
  renderRoute('/o/acme/overview');
  const strip = await screen.findByRole('alert', { name: 'Server not ready' });
  expect(within(strip).getByText('kek: failed')).toBeInTheDocument();
  expect(within(strip).queryByText('vault: failed')).not.toBeInTheDocument();
  expect(within(strip).getByText('vault: degraded')).toBeInTheDocument();
});

it('healthy renders nothing', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok' } })),
  );
  renderRoute('/o/acme/overview');
  await screen.findByText('No certificates yet.');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('failed kek still listed', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get('*/readyz', () => HttpResponse.json({ status: 'unavailable', checks: { database: 'ok', kek: 'failed' } }, { status: 503 })),
  );
  renderRoute('/o/acme/overview');
  const strip = await screen.findByRole('alert', { name: 'Server not ready' });
  expect(within(strip).getByText('kek: failed')).toBeInTheDocument();
});
