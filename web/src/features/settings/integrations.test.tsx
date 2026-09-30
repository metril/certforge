import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, keysRunning, keysStatic, meWith, notificationsSettings, org, problem, prometheusSettings, smtpSettings, url } from '@/test/fixtures';
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

// Task 6: the real smtp/notifications/prometheus settings-section schemas
// (internal/notify/{smtp,notifications}.schema.json, internal/metrics/
// prometheus.schema.json), copied verbatim, same precedent as the vault
// schema above.
const smtpSchema = {
  title: 'Email (SMTP)',
  description: 'SMTP server CertForge uses to deliver email notification channels.',
  type: 'object',
  additionalProperties: false,
  properties: {
    host: { type: 'string', title: 'Host', description: 'SMTP server hostname.', maxLength: 253 },
    port: { type: 'integer', title: 'Port', description: 'SMTP server port.', minimum: 1, maximum: 65535, default: 587 },
    username: { type: 'string', title: 'Username', description: 'SMTP authentication username. Leave empty for no authentication.', maxLength: 256 },
    password: { type: 'string', title: 'Password', description: 'SMTP authentication password, used when username is set.', secret: true },
    from: { type: 'string', title: 'From address', description: 'Envelope and header From address. Required once host is set.', format: 'email' },
    security: { type: 'string', title: 'Security', description: 'How the SMTP connection is secured. A username requires starttls or tls.', enum: ['starttls', 'tls', 'none'], default: 'starttls' },
    timeoutSeconds: { type: 'integer', title: 'Timeout (seconds)', description: 'Per-connection timeout for SMTP calls.', minimum: 1, maximum: 60, default: 10 },
  },
  dependentRequired: { host: ['from'] },
};
const notificationsSchema = {
  title: 'Notifications',
  description: 'Behaviour shared by every notification channel: the SSRF policy for channel URLs, and the thresholds that trigger expiry and renewal-failure events.',
  type: 'object',
  additionalProperties: false,
  properties: {
    allowLoopbackUrls: { type: 'boolean', title: 'Allow loopback and link-local', description: 'Lets webhook, ntfy and Home Assistant channels, and external monitors, target loopback and link-local hosts.', default: false },
    expiryWarningDays: { type: 'integer', title: 'Expiry warning (days)', description: "How many days before a certificate version's notAfter a cert.expiring event is raised.", minimum: 1, maximum: 60, default: 7 },
    failureThreshold: { type: 'integer', title: 'Renewal failure threshold', description: 'Consecutive renewal failures for one certificate before a cert.renewal_failed event is raised, at most once per day.', minimum: 1, maximum: 10, default: 3 },
  },
};
const prometheusSchema = {
  title: 'Prometheus',
  description: 'Exposes a bearer-token-protected /metrics endpoint for Prometheus to scrape.',
  type: 'object',
  additionalProperties: false,
  properties: {
    enabled: { type: 'boolean', title: 'Enabled', description: 'Serves GET /metrics when on; the endpoint returns 404 when off.', default: false },
    bearerToken: { type: 'string', title: 'Bearer token', description: 'Token the scraper must send as "Authorization: Bearer <token>". Required once enabled, 16-256 characters.', secret: true, maxLength: 256 },
  },
};

const smtpSection = { section: 'smtp', schema: smtpSchema, value: smtpSettings as Record<string, unknown>, stored: null, storedSecrets: [] as string[] };
const notificationsSection = { section: 'notifications', schema: notificationsSchema, value: notificationsSettings, stored: null, storedSecrets: [] as string[] };
// storedSecrets starts empty (unlike vault's default `token`) so the
// existing vault-only tests' unscoped `getByText('Stored')` still finds
// exactly one match; tests that care about a stored bearerToken (Replace,
// secret-caching) set it explicitly.
const prometheusSection = { section: 'prometheus', schema: prometheusSchema, value: prometheusSettings, storedSecrets: [] as string[], stored: null };
const generalSection = { section: 'general', schema: {}, value: { baseUrl: 'https://certforge.example.com' }, stored: null, storedSecrets: [] as string[] };

function handlers(
  opts: {
    onPut?: (b: Record<string, unknown>) => void;
    onTest?: (b: unknown) => unknown;
    keys?: typeof keysStatic;
    smtp?: typeof smtpSection;
    notifications?: typeof notificationsSection;
    prometheus?: typeof prometheusSection;
    general?: typeof generalSection;
    onSmtpPut?: (b: Record<string, unknown>) => void;
    onPrometheusPut?: (b: Record<string, unknown>) => void;
    onSmtpTest?: (b: unknown) => void;
    smtpTestResult?: unknown;
  } = {},
) {
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
    http.get(url('/settings/smtp'), () => HttpResponse.json(opts.smtp ?? smtpSection)),
    http.put(url('/settings/smtp'), async ({ request }) => {
      const b = (await request.json()) as Record<string, unknown>;
      opts.onSmtpPut?.(b);
      return HttpResponse.json({ ...smtpSection, value: b });
    }),
    http.post(url('/settings/smtp/test'), async ({ request }) => {
      const b = await request.json();
      opts.onSmtpTest?.(b);
      return HttpResponse.json(opts.smtpTestResult ?? { status: 'delivered', durationMs: 120 });
    }),
    http.get(url('/settings/notifications'), () => HttpResponse.json(opts.notifications ?? notificationsSection)),
    http.put(url('/settings/notifications'), async ({ request }) => HttpResponse.json({ ...notificationsSection, value: await request.json() })),
    http.get(url('/settings/prometheus'), () => HttpResponse.json(opts.prometheus ?? prometheusSection)),
    http.put(url('/settings/prometheus'), async ({ request }) => {
      const b = (await request.json()) as Record<string, unknown>;
      opts.onPrometheusPut?.(b);
      return HttpResponse.json({ ...prometheusSection, value: b });
    }),
    http.get(url('/settings/general'), () => HttpResponse.json(opts.general ?? generalSection)),
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

// Batch 3 review (Critical, SchemaSection.tsx:150): the generic
// fieldErrorFromMessage always matched "re-enter the token" to the literal
// `token` property, which is hidden under AppRole — the error landed on no
// visible field. IntegrationsSection's mapSaveError routes it to whichever
// secret field is actually live.
it('re-enter the token maps to token under authMethod token', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  server.use(http.put(url('/settings/vault'), () => problem(422, 're-enter the token', {}, 'Invalid settings')));
  const { user } = renderRoute('/settings/integrations');
  const namespace = await screen.findByLabelText('Namespace');
  await user.type(namespace, 'team-a');
  // Task 6 added three more SchemaSections, each with its own "Save" —
  // scope to Vault's own section so this still finds exactly one.
  const vaultSection = screen.getByRole('heading', { name: 'Vault' }).closest('div')!.parentElement!;
  await user.click(within(vaultSection).getByRole('button', { name: 'Save' }));
  const tokenField = screen.getByText('Token').closest('div')!.parentElement!;
  expect(await within(tokenField).findByRole('alert')).toHaveTextContent('re-enter the token');
});

it('re-enter the token maps to secretId under authMethod approle', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  server.use(http.put(url('/settings/vault'), () => problem(422, 're-enter the token', {}, 'Invalid settings')));
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  await user.click(screen.getByRole('radio', { name: 'approle' }));
  await user.type(screen.getByLabelText('Role ID'), 'role-1');
  await user.type(screen.getByLabelText('Secret ID'), 'secret-1');
  const vaultSection = screen.getByRole('heading', { name: 'Vault' }).closest('div')!.parentElement!;
  await user.click(within(vaultSection).getByRole('button', { name: 'Save' }));
  const secretIdField = screen.getByText('Secret ID').closest('div')!.parentElement!;
  expect(await within(secretIdField).findByRole('alert')).toHaveTextContent('re-enter the token');
});

// Batch 3 review (Critical, IntegrationsSection.tsx:28): `ui:widget: hidden`
// alone leaves the other method's field (a stored token's `__unchanged__`
// sentinel, or a typed roleId/secretId) in the Save/Test body; the server
// 422s on it being present at all under the "wrong" authMethod, so a
// section with a stored token could never switch to AppRole. Both bodies
// must drop it.
it('switching to approle drops the stored token from Save and Test bodies', async () => {
  let put: Record<string, unknown> = {};
  let tested: Record<string, unknown> = {};
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers({ onPut: (b) => (put = b), onTest: (b) => { tested = b as Record<string, unknown>; return undefined; } }),
  );
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  await user.click(screen.getByRole('radio', { name: 'approle' }));
  await user.type(screen.getByLabelText('Role ID'), 'role-1');
  await user.type(screen.getByLabelText('Secret ID'), 'secret-1');
  await user.click(screen.getByRole('button', { name: 'Test connection' }));
  await waitFor(() => expect(tested.roleId).toBe('role-1'));
  expect(tested).not.toHaveProperty('token');
  const vaultSection = screen.getByRole('heading', { name: 'Vault' }).closest('div')!.parentElement!;
  await user.click(within(vaultSection).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put.roleId).toBe('role-1'));
  expect(put).not.toHaveProperty('token');
});

it('switching back to token drops roleId and secretId from Save and Test bodies', async () => {
  let put: Record<string, unknown> = {};
  let tested: Record<string, unknown> = {};
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers({ onPut: (b) => (put = b), onTest: (b) => { tested = b as Record<string, unknown>; return undefined; } }),
  );
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  await user.click(screen.getByRole('radio', { name: 'approle' }));
  await user.type(screen.getByLabelText('Role ID'), 'role-1');
  await user.type(screen.getByLabelText('Secret ID'), 'secret-1');
  await user.click(screen.getByRole('radio', { name: 'token' }));
  await user.click(screen.getByRole('button', { name: 'Test connection' }));
  await waitFor(() => expect(tested.authMethod).toBe('token'));
  expect(tested).not.toHaveProperty('roleId');
  expect(tested).not.toHaveProperty('secretId');
  const vaultSection = screen.getByRole('heading', { name: 'Vault' }).closest('div')!.parentElement!;
  await user.click(within(vaultSection).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put.authMethod).toBe('token'));
  expect(put).not.toHaveProperty('roleId');
  expect(put).not.toHaveProperty('secretId');
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
  await screen.findByLabelText('Address');
  // Batch 3 review (Critical, integrations.test.tsx:119): type a real
  // secret and save it — the original version never typed one, so it could
  // not have caught a leak. Assert it neither ends up in the mutation cache
  // (Save is a direct call, not useMutation) nor anywhere in the query
  // cache (the server never echoes a secret back on GET).
  await user.click(screen.getByRole('button', { name: 'Replace Token' }));
  await user.type(screen.getByLabelText('Token'), 'hvs.REALSECRETVALUE');
  const vaultSection = screen.getByRole('heading', { name: 'Vault' }).closest('div')!.parentElement!;
  await user.click(within(vaultSection).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put.token).toBe('hvs.REALSECRETVALUE'));
  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  const cached = queryClient
    .getQueryCache()
    .getAll()
    .map((q) => JSON.stringify(q.state.data))
    .join('\n');
  expect(cached).not.toContain('hvs.REALSECRETVALUE');
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
  // Task 6 added three more SchemaSections (Email, Notifications,
  // Prometheus), each with its own "Save" button — scope to Vault's own
  // section (its `title="Vault"` heading's grandparent, the SchemaSection
  // root) so this test still finds exactly one.
  const vaultSection = screen.getByRole('heading', { name: 'Vault' }).closest('div')!.parentElement!;
  const save = within(vaultSection).getByRole('button', { name: 'Save' });
  const test = within(vaultSection).getByRole('button', { name: 'Test connection' });
  expect(save).toBeDisabled();
  expect(test).toBeDisabled();
  await user.hover(test);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the settings:write permission');
});

// Task 6: Settings → Integrations gains Email (SMTP), Notifications and
// Prometheus, each its own SchemaSection beside Vault.

it('renders email, notifications and prometheus sections', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/integrations');
  await screen.findByLabelText('Address');
  expect(screen.getByRole('heading', { name: 'Email (SMTP)' })).toBeInTheDocument();
  expect(screen.getByLabelText('Host')).toHaveValue(smtpSettings.host);
  expect(screen.getByLabelText('From address')).toHaveValue(smtpSettings.from);
  expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
  expect(screen.getByLabelText('Expiry warning (days)')).toHaveValue(notificationsSettings.expiryWarningDays);
  expect(screen.getByRole('heading', { name: 'Prometheus' })).toBeInTheDocument();
  expect(screen.getByLabelText('Bearer token')).toBeInTheDocument();
});

it('smtp test sends to and shows delivered chip', async () => {
  let tested: unknown;
  server.use(...authHandlers({ authed: true }), ...handlers({ onSmtpTest: (b) => { tested = b; } }));
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');
  await user.type(screen.getByLabelText('Send to'), 'ops@example.com');
  await user.click(screen.getByRole('button', { name: 'Send test email' }));
  expect(await screen.findByText('Delivered')).toBeInTheDocument();
  expect(screen.getByText(/120\s*ms/)).toBeInTheDocument();
  await waitFor(() => expect(tested).toEqual({ to: 'ops@example.com' }));
});

it('smtp test failure chip', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers({ smtpTestResult: { status: 'failed', error: 'connection refused', durationMs: 40 } }));
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');
  await user.type(screen.getByLabelText('Send to'), 'ops@example.com');
  await user.click(screen.getByRole('button', { name: 'Send test email' }));
  expect(await screen.findByText('Failed')).toBeInTheDocument();
  expect(screen.getByText('connection refused')).toBeInTheDocument();
});

it('smtp test disabled while dirty', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');
  await user.type(screen.getByLabelText('Send to'), 'ops@example.com');
  await user.type(screen.getByLabelText('Username'), 'x');
  const button = screen.getByRole('button', { name: 'Send test email' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Save your changes first');
});

it('smtp test disabled without saved host', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers({ smtp: { ...smtpSection, value: { port: 587, security: 'starttls', timeoutSeconds: 10 } } }),
  );
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Port');
  await user.type(screen.getByLabelText('Send to'), 'ops@example.com');
  const button = screen.getByRole('button', { name: 'Send test email' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Save an SMTP host first.');
});

it('re-enter password maps to password', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  server.use(http.put(url('/settings/smtp'), () => problem(422, 're-enter the password', {}, 'Invalid settings')));
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');
  await user.clear(screen.getByLabelText('Host'));
  await user.type(screen.getByLabelText('Host'), 'smtp2.example.com');
  const emailSection = screen.getByRole('heading', { name: 'Email (SMTP)' }).closest('div')!.parentElement!;
  await user.click(within(emailSection).getByRole('button', { name: 'Save' }));
  const passwordField = screen.getByText('Password').closest('div')!.parentElement!;
  expect(await within(passwordField).findByRole('alert')).toHaveTextContent('re-enter the password');
});

it('authentication requires TLS maps to username', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  server.use(http.put(url('/settings/smtp'), () => problem(422, 'authentication requires TLS', {}, 'Invalid settings')));
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');
  await user.click(screen.getByRole('radio', { name: 'none' }));
  const emailSection = screen.getByRole('heading', { name: 'Email (SMTP)' }).closest('div')!.parentElement!;
  await user.click(within(emailSection).getByRole('button', { name: 'Save' }));
  const usernameField = screen.getByText('Username').closest('div')!.parentElement!;
  expect(await within(usernameField).findByRole('alert')).toHaveTextContent('authentication requires TLS');
});

it('integration secrets not cached', async () => {
  let smtpPut: Record<string, unknown> = {};
  let promPut: Record<string, unknown> = {};
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers({
      smtp: { ...smtpSection, storedSecrets: ['password'] },
      prometheus: { ...prometheusSection, storedSecrets: ['bearerToken'] },
      onSmtpPut: (b) => (smtpPut = b),
      onPrometheusPut: (b) => (promPut = b),
    }),
  );
  const { user, queryClient } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');

  await user.click(screen.getByRole('button', { name: 'Replace Password' }));
  await user.type(screen.getByLabelText('Password'), 'REALSMTPSECRETVALUE');
  const emailSection = screen.getByRole('heading', { name: 'Email (SMTP)' }).closest('div')!.parentElement!;
  await user.click(within(emailSection).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(smtpPut.password).toBe('REALSMTPSECRETVALUE'));

  await user.click(screen.getByRole('button', { name: 'Replace Bearer token' }));
  await user.type(screen.getByLabelText('Bearer token'), 'REALPROMETHEUSSECRETVALUE12345');
  const promSection = screen.getByRole('heading', { name: 'Prometheus' }).closest('div')!.parentElement!;
  await user.click(within(promSection).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(promPut.bearerToken).toBe('REALPROMETHEUSSECRETVALUE12345'));

  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  const cached = queryClient
    .getQueryCache()
    .getAll()
    .map((q) => JSON.stringify(q.state.data))
    .join('\n');
  expect(cached).not.toContain('REALSMTPSECRETVALUE');
  expect(cached).not.toContain('REALPROMETHEUSSECRETVALUE12345');
});

it('scrape url has no token', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/integrations');
  expect(await screen.findByText('https://certforge.example.com/metrics')).toBeInTheDocument();
  const snippet = screen.getByLabelText('Prometheus scrape config');
  expect(snippet.textContent).toContain('credentials_file: /etc/prometheus/certforge.token');
  expect(snippet.textContent).not.toContain('__unchanged__');
});

it('prometheus off shows Off chip', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers({ prometheus: { ...prometheusSection, value: { enabled: false }, storedSecrets: [] } }));
  renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');
  // Scoped to PrometheusScrape's own root (not the whole Prometheus
  // section): the enabled switch's own offText also reads "Off".
  const scrapeRow = screen.getByText('Scrape URL').closest('div')!.parentElement!;
  expect(within(scrapeRow).getByText('Off')).toBeInTheDocument();
  expect(within(scrapeRow).queryByText(/\/metrics/)).not.toBeInTheDocument();
});

// Batch 3 review fix: PrometheusScrape used to key the Off chip/scrape URL
// on the live (possibly unsaved) draft SchemaSection hands its `actions`
// render-prop — toggling Enabled on without saving showed a scrape URL that
// still 404s until Save actually runs. It now reads its own
// `useQuery(settingsQuery('prometheus'))`, the saved value, so the row
// stays Off until the switch is actually saved.
it('scrape URL stays Off while the enabled switch is toggled but unsaved', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers({ prometheus: { ...prometheusSection, value: { enabled: false }, storedSecrets: [] } }));
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');
  const scrapeRow = screen.getByText('Scrape URL').closest('div')!.parentElement!;
  expect(within(scrapeRow).getByText('Off')).toBeInTheDocument();
  const promSection = screen.getByRole('heading', { name: 'Prometheus' }).closest('div')!.parentElement!;
  await user.click(within(promSection).getByRole('switch', { name: 'Enabled' }));
  expect(within(scrapeRow).getByText('Off')).toBeInTheDocument();
  expect(within(scrapeRow).queryByText(/\/metrics/)).not.toBeInTheDocument();
});

it('read-only user sees disabled tests and saves', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    ...handlers(),
  );
  const { user } = renderRoute('/settings/integrations');
  await screen.findByLabelText('Host');
  const emailSection = screen.getByRole('heading', { name: 'Email (SMTP)' }).closest('div')!.parentElement!;
  const save = within(emailSection).getByRole('button', { name: 'Save' });
  const test = within(emailSection).getByRole('button', { name: 'Send test email' });
  expect(save).toBeDisabled();
  expect(test).toBeDisabled();
  await user.hover(test);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the settings:write permission');
});
