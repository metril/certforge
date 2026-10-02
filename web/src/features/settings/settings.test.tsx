import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeAll, beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, ca, keysStatic, meWith, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// I4 (flaky "saves the General section from its schema"): SettingsPage
// (via $section.tsx's route-level code splitting) is the first thing in
// this file to pull in RJSF, Ajv and tldts's public suffix list — a large,
// one-time synchronous parse — the *first* time any test in this worker
// renders it. That cold load can by itself eat into a `waitFor`'s default
// budget before the section's own network round trip even starts. Pre-
// importing the module (not rendering it — no router/providers exist yet
// here) in `beforeAll` pays that cost once, up front, outside any test's own
// timing budget.
beforeAll(async () => {
  await import('./SettingsPage');
});

// The full set of ISSUANCE_FIELDS keys, all-null (the "nothing overridden"
// PUT payload review fix round 1's #1/#3 requires — every save sends every
// field explicitly, `null` for one that isn't overridden).
const allNull = {
  caId: null,
  accountId: null,
  keyType: null,
  renewPolicy: null,
  preferredChain: null,
  reuseKey: null,
  mustStaple: null,
  propagationSeconds: null,
  resolvers: null,
  verificationRules: null,
};

const puts: Record<string, unknown> = {};
beforeEach(() => {
  for (const k of Object.keys(puts)) delete puts[k];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs'), () => HttpResponse.json({ items: [{ id: 'org-1', slug: 'acme', name: 'Acme' }] })),
    http.get(url('/settings/general'), () =>
      HttpResponse.json({ schema: { type: 'object', properties: { baseUrl: { type: 'string', title: 'Base URL', format: 'uri' } } }, value: { baseUrl: 'https://a.example' }, stored: null }),
    ),
    http.get(url('/settings/backup'), () =>
      HttpResponse.json({
        schema: { type: 'object', properties: { kekEscrowConfirmed: { type: 'boolean', title: 'KEK escrow confirmed', description: 'Stored safely outside this server.' } } },
        value: { kekEscrowConfirmed: false },
        stored: null,
      }),
    ),
    http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok' } })),
    http.get(url('/keys/status'), () => HttpResponse.json(keysStatic)),
    // Mirrors internal/issuance/defaults.go's BuiltinDefaults() in `value`
    // (preflight A8/A9: caId, accountId, propagationSeconds stay absent
    // until explicitly saved) and internal/settings/store.go's GetSection
    // in `stored: null` (review fix round 1, #1): the section has never
    // actually been saved, even though `value` already shows a concrete
    // built-in-filled display.
    http.get(url('/settings/issuance_defaults'), () =>
      HttpResponse.json({
        schema: {},
        value: { keyType: 'ec256', renewPolicy: { mode: 'percent', value: 33, useAri: false }, preferredChain: '', reuseKey: false, mustStaple: false, resolvers: [] },
        stored: null,
      }),
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
  const { user, queryClient } = renderRoute('/settings/general');
  // Fix round 1 (Take now #5): baseUrl drives the callback URL Authentication
  // shows (AuthMethods.oidcCallbackUrl) — seed the auth-methods query into
  // the cache so invalidateQueries has something to mark stale, then check
  // it actually did.
  queryClient.setQueryData(['auth-methods'], { oidcEnabled: false, localEnabled: true, oidcCallbackUrl: 'https://a.example/api/v1/auth/oidc/callback' });
  const input = await screen.findByLabelText('Base URL');
  await user.clear(input);
  await user.type(input, 'https://b.example');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(puts.general).toEqual({ baseUrl: 'https://b.example' }));
  expect(queryClient.getQueryState(['auth-methods'])?.isInvalidated).toBe(true);
});

it('lists organizations read-only under General', async () => {
  renderRoute('/settings/general');
  expect(await screen.findByText('Acme')).toBeInTheDocument();
  expect(screen.getByText('acme')).toBeInTheDocument();
});

// Task 7: the Encryption key card (fed by GET /keys/status) replaces
// KekStatus (which read /readyz's checks.kek); its own coverage
// (kind/canary/previous/rewrap/permissions/polling) lives in keys.test.tsx.
it('shows the encryption key card and saves the escrow switch', async () => {
  const { user } = renderRoute('/settings/backup');
  expect(await screen.findByText('Static')).toBeInTheDocument();
  expect(screen.getByText('Canary OK')).toBeInTheDocument();
  await user.click(screen.getByRole('switch', { name: 'KEK escrow confirmed' }));
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(puts.backup).toEqual({ kekEscrowConfirmed: true }));
});

it('shows each Org-tab field badge from the effective endpoint, not a raw-value comparison', async () => {
  renderRoute('/settings/issuance-defaults?scope=org');
  const caField = within(await screen.findByRole('group', { name: 'Certificate authority' }));
  expect(await caField.findByRole('button', { name: 'Global' })).toBeInTheDocument();
  expect(caField.getByText(ca.name)).toBeInTheDocument();

  const keyTypeField = within(screen.getByRole('group', { name: 'Key type' }));
  expect(keyTypeField.getByRole('button', { name: 'Built-in' })).toBeInTheDocument();
});

it("the Org tab's chain tooltip reflects the raw stored global value, not the built-in-filled one", async () => {
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  const keyTypeField = within(await screen.findByRole('group', { name: 'Key type' }));
  await user.click(keyTypeField.getByRole('button', { name: 'Built-in' }));
  // stored is null (never saved): the Global entry says "server default",
  // not the built-in "EC P-256" the Default badge's own effective value
  // shows — otherwise the badge and its own tooltip would disagree.
  await waitFor(() => expect(document.querySelector('[data-slot="popover-content"]')).toHaveTextContent('Global: not set'));
});

it('overrides one org default and sends the rest as explicit null', async () => {
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  await user.click(await screen.findByRole('switch', { name: 'Override Key type' }));
  await user.click(screen.getByRole('radio', { name: 'RSA 2048' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  await waitFor(() => expect(puts.org).toEqual({ ...allNull, keyType: 'rsa2048' }));
});

it('shows a 422 reference error next to its field', async () => {
  server.use(
    http.put(url('/orgs/org-1/issuance-defaults'), () =>
      HttpResponse.json({ type: 'about:blank', title: 'Invalid caId', status: 422, detail: 'no such CA in this org' }, { status: 422, headers: { 'Content-Type': 'application/problem+json' } }),
    ),
  );
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  const caField = within(await screen.findByRole('group', { name: 'Certificate authority' }));
  await user.click(caField.getByRole('switch', { name: 'Override Certificate authority' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  expect(await caField.findByRole('alert')).toHaveTextContent('no such CA in this org');
});

it('falls back to the banner for a mapped 422 on a field that is not overridden', async () => {
  server.use(
    http.put(url('/orgs/org-1/issuance-defaults'), () =>
      HttpResponse.json(
        { type: 'about:blank', title: 'Invalid keyType', status: 422, detail: 'must be one of rsa2048, rsa3072, rsa4096, ec256, ec384' },
        { status: 422, headers: { 'Content-Type': 'application/problem+json' } },
      ),
    ),
  );
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  // Override a different field so Save is enabled; Key type itself stays
  // inherited, so InheritableField renders no editor row to put the error
  // next to — it must still reach the banner, not vanish (review fix round 1, #5).
  await user.click(await screen.findByRole('switch', { name: 'Override Must-Staple' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('must be one of rsa2048, rsa3072, rsa4096, ec256, ec384');
});

it('clearing an overridden lookup field resets to inherited, not an empty string', async () => {
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  const caField = within(await screen.findByRole('group', { name: 'Certificate authority' }));
  await user.click(await caField.findByRole('switch', { name: 'Override Certificate authority' }));
  await user.click(await caField.findByRole('button', { name: 'Clear Certificate authority' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  await waitFor(() => expect(puts.org).toEqual(allNull));
});

// Fix round 1 (review, item 5): the verificationRules field (Task 13's
// VerificationRulesEditor, wired into ISSUANCE_FIELDS) renders under
// Override and its rules round-trip through a save like any other field.
it('renders and saves the Verification rules field', async () => {
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  const rulesField = within(await screen.findByRole('group', { name: 'Verification rules' }));
  await user.click(rulesField.getByRole('switch', { name: 'Override Verification rules' }));
  expect(await rulesField.findByLabelText('Rule 1 match')).toHaveValue('*');
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  await waitFor(() => expect((puts.org as Record<string, unknown>).verificationRules).toEqual([{ match: '*', method: 'dns-01' }]));
});

it('disables Override for a lookup field with nothing to choose', async () => {
  server.use(http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])), http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])));
  renderRoute('/settings/issuance-defaults?scope=org');
  const caField = within(await screen.findByRole('group', { name: 'Certificate authority' }));
  expect(await caField.findByRole('switch', { name: 'Override Certificate authority' })).toBeDisabled();
  expect(caField.getByText('No CAs yet')).toBeInTheDocument();
});

it('resets an org override: PUT sends null and keeps its sibling, badge settles to the refetched effective source', async () => {
  let orgBody: Record<string, unknown> = { mustStaple: true, reuseKey: true };
  let effectiveBody: Record<string, unknown> = {
    caId: { value: null, source: 'default' },
    accountId: { value: null, source: 'default' },
    keyType: { value: 'ec256', source: 'default' },
    renewPolicy: { value: { mode: 'percent', value: 33, useAri: false }, source: 'default' },
    preferredChain: { value: '', source: 'default' },
    reuseKey: { value: true, source: 'org' },
    mustStaple: { value: true, source: 'org' },
    propagationSeconds: { value: 120, source: 'default' },
    resolvers: { value: [], source: 'default' },
  };
  server.use(
    http.get(url('/orgs/org-1/issuance-defaults'), () => HttpResponse.json(orgBody)),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json(effectiveBody)),
    http.put(url('/orgs/org-1/issuance-defaults'), async ({ request }) => {
      const body = (await request.json()) as Record<string, unknown>;
      puts.org = body;
      orgBody = { reuseKey: body.reuseKey };
      effectiveBody = { ...effectiveBody, mustStaple: { value: false, source: 'default' } };
      return HttpResponse.json(orgBody);
    }),
  );
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  const mustStapleField = within(await screen.findByRole('group', { name: 'Must-Staple' }));
  expect(await mustStapleField.findByRole('switch', { name: 'Override Must-Staple' })).toBeChecked();

  await user.click(mustStapleField.getByRole('button', { name: 'Use Global value' }));
  // Before the save lands, `effective` still says 'org' with the old value
  // — showing that here (instead of "Inherited after save"/"Pending") would
  // be stale (review fix round 1, #3).
  expect(mustStapleField.getByText('Pending')).toBeInTheDocument();
  expect(mustStapleField.getByText('Inherited after save')).toBeInTheDocument();

  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  await waitFor(() => expect(puts.org).toEqual({ ...allNull, mustStaple: null, reuseKey: true }));
  await waitFor(() => expect(mustStapleField.getByRole('button', { name: 'Built-in' })).toBeInTheDocument());
});

it('Global tab: unsaved fields show Default (not already Overridden), with the one-sentence copy and built-in effective value', async () => {
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  await user.click(await screen.findByRole('tab', { name: 'Global' }));
  // M2: the "Fields left as Default..." copy is a help tooltip now, not an
  // inline paragraph — hover its info icon (scoped past the many other
  // per-field Help buttons on this tab) to read it.
  const globalHeader = screen.getByText('Built-in defaults').closest('div')!;
  await user.hover(within(globalHeader).getByRole('button', { name: 'Help' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent("Most specific wins: Certificate > Organization > Global > Built-in (shipped with CertForge). Fields left unset here use the built-in value.");
  const keyTypeField = within(screen.getByRole('group', { name: 'Key type' }));
  expect(keyTypeField.getByRole('button', { name: 'Built-in' })).toBeInTheDocument();
  expect(keyTypeField.getByRole('switch', { name: 'Override Key type' })).not.toBeChecked();
  expect(keyTypeField.getByText('EC P-256')).toBeInTheDocument();
});

it('Global tab save: an untouched field is sent as explicit null, not the built-in display value', async () => {
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  await user.click(await screen.findByRole('tab', { name: 'Global' }));
  await user.click(await screen.findByRole('switch', { name: 'Override Must-Staple' }));
  await user.click(screen.getByRole('button', { name: 'Save global defaults' }));
  // Overriding Must-Staple seeds it from the built-in (false); every other
  // field the operator never touched is explicit null, not `value`'s
  // built-in-filled 'ec256'/33%/etc — the bug review fix round 1 #1 fixes.
  await waitFor(() => expect(puts.issuance_defaults).toEqual({ ...allNull, mustStaple: false }));
});

it('Global tab save: preserves verificationRules, a field this page does not render (review fix round 2)', async () => {
  const verificationRules = [{ match: '*.example.com', method: 'dns-01', dnsCredentialId: 'd-1' }];
  server.use(
    http.get(url('/settings/issuance_defaults'), () =>
      HttpResponse.json({
        schema: {},
        value: { keyType: 'ec256', renewPolicy: { mode: 'percent', value: 33, useAri: false }, preferredChain: '', reuseKey: false, mustStaple: false, resolvers: [], verificationRules },
        // stored already carries verificationRules (some earlier task set
        // it); this save only touches Must-Staple.
        stored: { verificationRules },
      }),
    ),
  );
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  await user.click(await screen.findByRole('tab', { name: 'Global' }));
  await user.click(await screen.findByRole('switch', { name: 'Override Must-Staple' }));
  await user.click(screen.getByRole('button', { name: 'Save global defaults' }));
  // A "replace the whole object" PUT built only from ISSUANCE_FIELDS would
  // drop verificationRules (no entry for it) — fullPayload now spreads the
  // existing value first, so it survives an unrelated save.
  await waitFor(() => expect((puts.issuance_defaults as Record<string, unknown>).verificationRules).toEqual(verificationRules));
});

it('Org tab save: preserves verificationRules, a field this page does not render (review fix round 2)', async () => {
  const verificationRules = [{ match: '*.example.com', method: 'dns-01', dnsCredentialId: 'd-1' }];
  server.use(http.get(url('/orgs/org-1/issuance-defaults'), () => HttpResponse.json({ verificationRules })));
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  await user.click(await screen.findByRole('switch', { name: 'Override Must-Staple' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  await waitFor(() => expect((puts.org as Record<string, unknown>).verificationRules).toEqual(verificationRules));
});

it('keeps the tab header wrapping at phone width', async () => {
  renderRoute('/settings/issuance-defaults?scope=org');
  const tablist = await screen.findByRole('tablist');
  expect(tablist.parentElement?.className).toContain('flex-wrap');
});

// Fix round 2 (Important #1): the Global tab needs settings:write (global-
// only); the Org tab needs certs:write in that org. A viewer has neither,
// so both Save buttons stay disabled even once dirty.
it('disables Save global/org defaults for a viewer, even once dirty', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))));
  const { user } = renderRoute('/settings/issuance-defaults?scope=org');
  await user.click(await screen.findByRole('switch', { name: 'Override Key type' }));
  expect(screen.getByRole('button', { name: 'Save org defaults' })).toBeDisabled();
  await user.click(await screen.findByRole('tab', { name: 'Global' }));
  await user.click(await screen.findByRole('switch', { name: 'Override Must-Staple' }));
  expect(screen.getByRole('button', { name: 'Save global defaults' })).toBeDisabled();
});

it('Issuance defaults opens on Global, ?scope=org selects the Organization tab, and the chain links to the other level', async () => {
  const { router, user } = renderRoute('/settings/issuance-defaults');
  expect(await screen.findByRole('tab', { name: 'Global', selected: true })).toBeInTheDocument();
  const keyType = within(screen.getByRole('group', { name: 'Key type' }));
  await user.click(keyType.getByRole('button', { name: 'Built-in' }));
  const pop = await waitFor(() => {
    const el = document.querySelector('[data-slot="popover-content"]') as HTMLElement;
    expect(el).not.toBeNull();
    return within(el);
  });
  expect(pop.getByRole('link', { name: 'Organization' })).toHaveAttribute('href', '/settings/issuance-defaults?scope=org');
  expect(document.querySelector('[data-slot="popover-content"]')).toHaveTextContent('Built-in: EC P-256');
  await user.keyboard('{Escape}');
  const strip = within(screen.getByLabelText('Defaults precedence'));
  await user.click(strip.getByRole('button', { name: 'Organization' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ scope: 'org' }));
  await user.click(within(screen.getByLabelText('Defaults precedence')).getByRole('button', { name: 'Global' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ scope: 'global' }));
  await user.click(screen.getAllByRole('tab')[1]!);
  await waitFor(() => expect(router.state.location.search).toMatchObject({ scope: 'org' }));
});
