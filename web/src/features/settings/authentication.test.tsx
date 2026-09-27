import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeBinding, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// The real authentication schema (internal/authn/settings.go's authSchema),
// copied verbatim per controller ruling E5/A1 so the RJSF theme mapping is
// exercised against the actual field set: array-of-plain-string
// (scopes/trustedProxies) -> ListInput, and clientId (maxLength 200, at the
// textarea threshold) stays a single-line input.
const schema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    enabled: { type: 'boolean', title: 'Single sign-on', description: 'Show the single sign-on button on the login page.', default: false },
    issuer: {
      type: 'string',
      title: 'Issuer URL',
      description: 'The OIDC issuer; CertForge reads its discovery document.',
      pattern: '^https?://[^\\s]+$',
      examples: ['https://login.example.com/realms/main'],
    },
    clientId: {
      type: 'string',
      title: 'Client ID',
      description: 'The client registered for CertForge at the identity provider.',
      maxLength: 200,
      examples: ['certforge'],
    },
    clientSecret: { type: 'string', title: 'Client secret', description: 'Leave empty for a public client using PKCE only.', secret: true, maxLength: 1024 },
    scopes: {
      type: 'array',
      title: 'Scopes',
      description: 'Requested scopes; must include openid.',
      items: { type: 'string' },
      default: ['openid', 'profile', 'email', 'groups'],
    },
    groupsClaim: { type: 'string', title: 'Groups claim', description: "ID token claim listing the user's groups; group role bindings match these.", default: 'groups', maxLength: 128 },
    sessionTtlHours: { type: 'integer', title: 'Session lifetime (hours)', description: 'How long a sign-in lasts. Applies to new sessions.', minimum: 1, maximum: 720, default: 12 },
    trustedProxies: {
      type: 'array',
      title: 'Trusted proxies',
      description: "Addresses or CIDRs of reverse proxies whose X-Forwarded-For is believed.",
      items: { type: 'string' },
      default: [],
      examples: [['10.0.0.0/8']],
    },
    loginRatePerMinute: { type: 'integer', title: 'Login rate limit (per minute)', description: 'Login attempts allowed per client address per minute. 0 disables the limit.', minimum: 0, default: 10 },
    loginBurst: { type: 'integer', title: 'Login rate limit burst', description: 'Login attempts a client may make in a single burst before the per-minute rate applies.', minimum: 1, default: 5 },
  },
};
const section = {
  section: 'authentication', schema,
  value: { enabled: true, issuer: 'https://idp.example.com', clientId: 'certforge', sessionTtlHours: 12 },
  stored: null, storedSecrets: ['clientSecret'],
};

function handlers(onPut?: (b: Record<string, unknown>) => void, onTest?: (b: unknown) => unknown) {
  return [
    http.get(url('/settings/authentication'), () => HttpResponse.json(section)),
    http.get(url('/auth/methods'), () =>
      HttpResponse.json({ oidcEnabled: true, localEnabled: true, oidcCallbackUrl: 'https://certs.example.com/api/v1/auth/oidc/callback' })),
    http.put(url('/settings/authentication'), async ({ request }) => {
      const b = (await request.json()) as Record<string, unknown>;
      onPut?.(b);
      return HttpResponse.json({ ...section, value: b });
    }),
    http.post(url('/settings/authentication/test'), async ({ request }) =>
      HttpResponse.json(onTest?.(await request.json()) ?? { ok: true, keys: 2, tokenEndpoint: 'https://idp.example.com/token' })),
    http.get(url('/role-bindings'), () =>
      HttpResponse.json({ items: [makeBinding({ id: 'g-1', subjectType: 'oidc_group', subject: 'ops', subjectLabel: 'ops', role: 'operator' })] })),
  ];
}

it('keeps the stored client secret when saving other fields', async () => {
  let put: Record<string, unknown> = {};
  server.use(...authHandlers({ authed: true }), ...handlers((b) => (put = b)));
  const { user } = renderRoute('/settings/authentication');
  expect(await screen.findByText('Stored')).toBeInTheDocument();
  expect(screen.getByText('https://certs.example.com/api/v1/auth/oidc/callback')).toBeInTheDocument();
  const issuer = screen.getByLabelText('Issuer URL');
  await user.clear(issuer);
  await user.type(issuer, 'https://login.example.com');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await screen.findByText('Settings saved');
  expect(put.clientSecret).toBe('__unchanged__');
  expect(put.issuer).toBe('https://login.example.com');
});

// Review fix round 1 (Important #1): FieldTemplate's showLabel special-cases
// ui:field: 'listArray' so a plain-string-array field keeps its visible
// label and help tip despite RJSF's own displayLabel=false for it.
it('shows a label and help tip for the scopes listArray field', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user } = renderRoute('/settings/authentication');
  await screen.findByText('Stored');
  const field = screen.getByText('Scopes').closest('div')!;
  await user.hover(within(field).getByRole('button', { name: 'Help' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Requested scopes; must include openid.');
});

it('a trusted proxy is written at its own field, not over the whole form (fix round 1, Critical)', async () => {
  // Regression for the array Field's onChange(v, []) bug: an empty RJSF
  // path means "replace the root", so adding a trusted proxy silently
  // replaced the whole form's data with just that one-element array —
  // `issuer`/`clientId` (and every other field) would have gone missing
  // from the PUT body. `put` (not a toast, which sonner's module-level
  // queue can still be showing from the previous test) is the signal here.
  let put: Record<string, unknown> | undefined;
  server.use(...authHandlers({ authed: true }), ...handlers((b) => (put = b)));
  const { user } = renderRoute('/settings/authentication');
  await screen.findByText('Stored');
  const proxies = screen.getByLabelText('Trusted proxies');
  await user.type(proxies, '10.0.0.0/8{Enter}');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toBeDefined());
  expect(put?.trustedProxies).toEqual(['10.0.0.0/8']);
  expect(put?.issuer).toBe('https://idp.example.com');
  expect(put?.clientId).toBe('certforge');
});

it('a 422 naming a field shows an inline error next to it (fix round 1, Take now #6)', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  server.use(
    http.put(url('/settings/authentication'), () =>
      problem(422, 'trustedProxies: "not-an-ip" is not an IP address or CIDR', {}, 'Invalid settings')),
  );
  const { user } = renderRoute('/settings/authentication');
  await screen.findByText('Stored');
  const proxies = screen.getByLabelText('Trusted proxies');
  await user.type(proxies, 'not-an-ip{Enter}');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('trustedProxies: "not-an-ip" is not an IP address or CIDR');
});

it('tests the issuer typed in the form', async () => {
  let tested: unknown;
  server.use(...authHandlers({ authed: true }), ...handlers(undefined, (b) => { tested = b; return undefined; }));
  const { user } = renderRoute('/settings/authentication');
  await user.click(await screen.findByRole('button', { name: 'Test connection' }));
  expect(tested).toEqual({ issuer: 'https://idp.example.com' });
  expect(await screen.findByRole('status')).toHaveTextContent('2 signing keys found');
});

it('shows why a test failed', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers(undefined, () => ({ ok: false, detail: 'discovery: 404 Not Found' })));
  const { user } = renderRoute('/settings/authentication');
  await user.click(await screen.findByRole('button', { name: 'Test connection' }));
  expect(await screen.findByRole('status')).toHaveTextContent('discovery: 404 Not Found');
});

it('lists group mappings and adds one', async () => {
  let body: unknown;
  server.use(...authHandlers({ authed: true }), ...handlers(),
    http.post(url('/role-bindings'), async ({ request }) => { body = await request.json(); return HttpResponse.json(makeBinding(), { status: 201 }); }));
  const { user } = renderRoute('/settings/authentication');
  const mappings = await screen.findByRole('region', { name: 'Group mappings' });
  expect(await within(mappings).findByText('ops')).toBeInTheDocument();
  await user.click(within(mappings).getByRole('button', { name: 'Add mapping' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add group mapping' });
  expect(within(sheet).queryByRole('group', { name: 'Subject type' })).not.toBeInTheDocument();
  await user.type(within(sheet).getByLabelText('Group'), 'auditors');
  await user.click(within(sheet).getByRole('radio', { name: 'Auditor' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(body).toEqual({ subjectType: 'oidc_group', subject: 'auditors', role: 'auditor', orgId: org.id });
});

it('is read-only without settings:write', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    ...handlers(),
  );
  const { user } = renderRoute('/settings/authentication');
  await screen.findByText('Stored');
  // Review fix round 1 (Task 9, SchemaSection.tsx): Save is shown disabled
  // behind PermissionTip, never hidden, matching the global rule that a
  // control the caller cannot use stays visible-but-disabled.
  const save = screen.getByRole('button', { name: 'Save' });
  expect(save).toBeDisabled();
  await user.hover(save);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the settings:write permission');
  expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument();
});
