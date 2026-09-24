import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, ca, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

const puts: Record<string, unknown> = {};
beforeEach(() => {
  for (const k of Object.keys(puts)) delete puts[k];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs'), () => HttpResponse.json({ items: [{ id: 'org-1', slug: 'acme', name: 'Acme' }] })),
    http.get(url('/settings/general'), () =>
      HttpResponse.json({ schema: { type: 'object', properties: { baseUrl: { type: 'string', title: 'Base URL', format: 'uri' } } }, value: { baseUrl: 'https://a.example' } }),
    ),
    http.get(url('/settings/backup'), () =>
      HttpResponse.json({
        schema: { type: 'object', properties: { kekEscrowConfirmed: { type: 'boolean', title: 'KEK escrow confirmed', description: 'Stored safely outside this server.' } } },
        value: { kekEscrowConfirmed: false },
      }),
    ),
    http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok' } })),
    // Mirrors internal/issuance/defaults.go's BuiltinDefaults(): caId,
    // accountId and propagationSeconds stay absent until explicitly saved
    // (preflight A8/A9).
    http.get(url('/settings/issuance_defaults'), () =>
      HttpResponse.json({ schema: {}, value: { keyType: 'ec256', renewPolicy: { mode: 'percent', value: 33, useAri: false }, preferredChain: '', reuseKey: false, mustStaple: false, resolvers: [] } }),
    ),
    http.get(url('/orgs/org-1/issuance-defaults'), () => HttpResponse.json({})),
    // The effective endpoint is the only source of truth for a field's
    // badge (controller ruling): keyType here is 'default' even though the
    // settings-section GET above shows a concrete 'ec256' value, and caId
    // is 'global' even though the org's own value (above) is unset —
    // proving the UI reads this, not a raw-value comparison.
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () =>
      HttpResponse.json({
        caId: { value: ca.id, source: 'global' },
        accountId: { value: null, source: 'default' },
        keyType: { value: 'ec256', source: 'default' },
        renewPolicy: { value: { mode: 'percent', value: 33, useAri: false }, source: 'default' },
      }),
    ),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.put(url('/settings/:section'), async ({ request, params }) => {
      puts[params.section as string] = await request.json();
      return HttpResponse.json({});
    }),
    http.put(url('/orgs/org-1/issuance-defaults'), async ({ request }) => {
      const body = await request.json();
      puts.org = body;
      return HttpResponse.json(body);
    }),
  );
});

it('saves the General section from its schema', async () => {
  const { user } = renderRoute('/settings/general');
  const input = await screen.findByLabelText('Base URL');
  await user.clear(input);
  await user.type(input, 'https://b.example');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(puts.general).toEqual({ baseUrl: 'https://b.example' }));
});

it('lists organizations read-only under General', async () => {
  renderRoute('/settings/general');
  expect(await screen.findByText('Acme')).toBeInTheDocument();
  expect(screen.getByText('acme')).toBeInTheDocument();
});

it('shows the KEK status from /readyz and saves the escrow switch', async () => {
  const { user } = renderRoute('/settings/backup');
  expect(await screen.findByText('OK')).toBeInTheDocument();
  await user.click(screen.getByRole('switch', { name: 'KEK escrow confirmed' }));
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(puts.backup).toEqual({ kekEscrowConfirmed: true }));
});

it('shows a failed KEK check', async () => {
  server.use(http.get('*/readyz', () => HttpResponse.json({ status: 'unavailable', checks: { database: 'ok', kek: 'failed' } })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Failed')).toBeInTheDocument();
});

it('shows each field badge from the effective endpoint, not a raw-value comparison', async () => {
  renderRoute('/settings/issuance-defaults');
  const caField = within(await screen.findByRole('group', { name: 'Certificate authority' }));
  expect(await caField.findByRole('button', { name: 'Global' })).toBeInTheDocument();
  expect(caField.getByText(ca.name)).toBeInTheDocument();

  const keyTypeField = within(screen.getByRole('group', { name: 'Key type' }));
  expect(keyTypeField.getByRole('button', { name: 'Default' })).toBeInTheDocument();
});

it('overrides one org default and leaves the rest inherited', async () => {
  const { user } = renderRoute('/settings/issuance-defaults');
  await user.click(await screen.findByRole('switch', { name: 'Override Key type' }));
  await user.click(screen.getByRole('radio', { name: 'RSA 2048' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  await waitFor(() => expect(puts.org).toEqual({ keyType: 'rsa2048' }));
});

it('shows a 422 reference error next to its field', async () => {
  server.use(
    http.put(url('/orgs/org-1/issuance-defaults'), () =>
      HttpResponse.json({ type: 'about:blank', title: 'Invalid caId', status: 422, detail: 'no such CA in this org' }, { status: 422, headers: { 'Content-Type': 'application/problem+json' } }),
    ),
  );
  const { user } = renderRoute('/settings/issuance-defaults');
  const caField = within(await screen.findByRole('group', { name: 'Certificate authority' }));
  await user.click(caField.getByRole('switch', { name: 'Override Certificate authority' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  expect(await caField.findByRole('alert')).toHaveTextContent('no such CA in this org');
});
