import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, keysRunning, keysStatic, meWith, org, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// The real vault settings schema (internal/vault's Settings, mirroring
// VaultSettings in api/schema.d.ts), copied verbatim per the authentication
// section's own precedent (authentication.test.tsx) so the RJSF theme
// mapping (segmented control for authMethod, secret widget for token/
// secretId, mono textarea for caPem) is exercised against the real field
// set, and so the token/roleId/secretId hide-by-authMethod uiSchemaOverrides
// runs against fields that actually carry the `secret: true` marker.
const schema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    address: { type: 'string', format: 'uri', title: 'Address', description: "Vault's base URL (http or https). Required once any other field below is set." },
    namespace: { type: 'string', title: 'Namespace', description: 'Vault Enterprise namespace; empty for open-source Vault or OpenBao.', maxLength: 128 },
    authMethod: { type: 'string', enum: ['token', 'approle'], title: 'Auth method', description: 'How CertForge logs in to Vault.', default: 'token' },
    token: { type: 'string', title: 'Token', description: 'Vault token, used when authMethod is token.', secret: true },
    roleId: { type: 'string', title: 'Role ID', description: 'AppRole role id.', maxLength: 128 },
    secretId: { type: 'string', title: 'Secret ID', description: 'AppRole secret id, used when authMethod is approle.', secret: true },
    caPem: { type: 'string', title: 'CA bundle', description: "Additional PEM-encoded certificates trusted for Vault's TLS", maxLength: 65536 },
    timeoutSeconds: { type: 'integer', title: 'Timeout (seconds)', description: 'Per-request timeout for calls to Vault.', minimum: 1, maximum: 60, default: 10 },
  },
};
const section = {
  section: 'vault', schema,
  value: { address: 'https://vault.example.com:8200', namespace: '', authMethod: 'token', timeoutSeconds: 10 },
  stored: null, storedSecrets: ['token'],
};

function handlers(opts: { onPut?: (b: Record<string, unknown>) => void; onTest?: (b: unknown) => unknown; keys?: typeof keysStatic } = {}) {
  return [
    http.get(url('/settings/vault'), () => HttpResponse.json(section)),
    http.get(url('/keys/status'), () => HttpResponse.json(opts.keys ?? keysStatic)),
    http.put(url('/settings/vault'), async ({ request }) => {
      const b = (await request.json()) as Record<string, unknown>;
      opts.onPut?.(b);
      return HttpResponse.json({ ...section, value: b });
    }),
    http.post(url('/settings/vault/test'), async ({ request }) =>
      HttpResponse.json(opts.onTest?.(await request.json()) ?? { ok: true, tokenTtlSeconds: 2_764_800, policies: ['default'], version: '1.15.0' })),
  ];
}

it('renders vault section', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/integrations');
  expect(await screen.findByLabelText('Address')).toHaveValue('https://vault.example.com:8200');
  expect(screen.getByRole('radio', { name: 'token' })).toBeChecked();
  expect(screen.getByText('Stored')).toBeInTheDocument(); // token, stored
  expect(screen.queryByLabelText('Role ID')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Secret ID')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Timeout (seconds)')).toHaveValue(10);
});

it('approle hides token', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  await user.click(screen.getByRole('radio', { name: 'approle' }));
  expect(screen.queryByText('Stored')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Role ID')).toBeInTheDocument();
  expect(screen.getByLabelText('Secret ID')).toBeInTheDocument();
});

it('auth method field carries the AppRole help tip', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  const field = screen.getByText('Auth method').closest('div')!;
  await user.hover(within(field).getByRole('button', { name: 'Help' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Role ID and secret ID from an AppRole');
});

it('test connection ok chip', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  await user.click(screen.getByRole('button', { name: 'Test connection' }));
  expect(await screen.findByText('Connected')).toBeInTheDocument();
  expect(screen.getByText(/TTL 32 d/)).toHaveTextContent('v1.15.0');
  expect(screen.getByText('default')).toBeInTheDocument();
});

it('test connection failure chip', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers({ onTest: () => ({ ok: false, error: 'connection refused' }) }));
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  await user.click(screen.getByRole('button', { name: 'Test connection' }));
  expect(await screen.findByText('Failed')).toBeInTheDocument();
  expect(screen.getByText('connection refused')).toBeInTheDocument();
});

it('test connection sends sentinel', async () => {
  let tested: Record<string, unknown> = {};
  server.use(...authHandlers({ authed: true }), ...handlers({ onTest: (b) => { tested = b as Record<string, unknown>; return undefined; } }));
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  await user.click(screen.getByRole('button', { name: 'Test connection' }));
  // The stored token is never re-typed here; it must still go out as the
  // sentinel, never left off (which would clear it) or sent as plain text.
  await waitFor(() => expect(tested.token).toBe('__unchanged__'));
});

it('result clears on edit', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  await user.click(screen.getByRole('button', { name: 'Test connection' }));
  expect(await screen.findByText('Connected')).toBeInTheDocument();
  await user.type(screen.getByLabelText('Namespace'), 'ns1');
  expect(screen.queryByText('Connected')).not.toBeInTheDocument();
});

it('vault secrets not cached', async () => {
  let put: Record<string, unknown> = {};
  server.use(...authHandlers({ authed: true }), ...handlers({ onPut: (b) => (put = b) }));
  const { user, queryClient } = renderRoute('/settings/integrations');
  const namespace = await screen.findByLabelText('Namespace');
  await user.type(namespace, 'team-a');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put.namespace).toBe('team-a'));
  expect(put.token).toBe('__unchanged__');
  // Save goes through a direct api.* call, not useMutation, so nothing
  // about it (including the sentinel-guarded token) ever lands in the
  // mutation cache.
  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
});

it('transit line only for vault-transit', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  expect(screen.queryByText('Transit KEK')).not.toBeInTheDocument();
});

it('shows the Transit KEK line for a vault-transit KEK', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers({ keys: { ...keysRunning, rewrap: null } }));
  renderRoute('/settings/integrations');
  expect(await screen.findByText('Transit KEK')).toBeInTheDocument();
  expect(screen.getByText(keysRunning.vaultAddress!)).toBeInTheDocument();
});

it('read-only user sees disabled test and save', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    ...handlers(),
  );
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  const save = screen.getByRole('button', { name: 'Save' });
  const test = screen.getByRole('button', { name: 'Test connection' });
  expect(save).toBeDisabled();
  expect(test).toBeDisabled();
  await user.hover(test);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the settings:write permission');
});
