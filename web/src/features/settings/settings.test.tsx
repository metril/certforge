import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, ca, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

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

it('shows a failed KEK check once, without repeating the chip word as raw text', async () => {
  server.use(http.get('*/readyz', () => HttpResponse.json({ status: 'unavailable', checks: { database: 'ok', kek: 'failed' } })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Failed')).toBeInTheDocument();
  // fetchReadiness sets message to the raw "failed" string; it must not
  // also render as its own line once the chip already says "Failed".
  expect(screen.queryByText('failed')).toBeNull();
});

it('shows each Org-tab field badge from the effective endpoint, not a raw-value comparison', async () => {
  renderRoute('/settings/issuance-defaults');
  const caField = within(await screen.findByRole('group', { name: 'Certificate authority' }));
  expect(await caField.findByRole('button', { name: 'Global' })).toBeInTheDocument();
  expect(caField.getByText(ca.name)).toBeInTheDocument();

  const keyTypeField = within(screen.getByRole('group', { name: 'Key type' }));
  expect(keyTypeField.getByRole('button', { name: 'Default' })).toBeInTheDocument();
});

it("the Org tab's chain tooltip reflects the raw stored global value, not the built-in-filled one", async () => {
  const { user } = renderRoute('/settings/issuance-defaults');
  const keyTypeField = within(await screen.findByRole('group', { name: 'Key type' }));
  await user.hover(keyTypeField.getByRole('button', { name: 'Default' }));
  // stored is null (never saved): the Global entry says "server default",
  // not the built-in "EC P-256" the Default badge's own effective value
  // shows — otherwise the badge and its own tooltip would disagree.
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Global: server default');
});

it('overrides one org default and sends the rest as explicit null', async () => {
  const { user } = renderRoute('/settings/issuance-defaults');
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
  const { user } = renderRoute('/settings/issuance-defaults');
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
  const { user } = renderRoute('/settings/issuance-defaults');
  // Override a different field so Save is enabled; Key type itself stays
  // inherited, so InheritableField renders no editor row to put the error
  // next to — it must still reach the banner, not vanish (review fix round 1, #5).
  await user.click(await screen.findByRole('switch', { name: 'Override Must-Staple' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('must be one of rsa2048, rsa3072, rsa4096, ec256, ec384');
});

it('clearing an overridden lookup field resets to inherited, not an empty string', async () => {
  const { user } = renderRoute('/settings/issuance-defaults');
  const caField = within(await screen.findByRole('group', { name: 'Certificate authority' }));
  await user.click(await caField.findByRole('switch', { name: 'Override Certificate authority' }));
  await user.click(await caField.findByRole('button', { name: 'Clear Certificate authority' }));
  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  await waitFor(() => expect(puts.org).toEqual(allNull));
});

it('disables Override for a lookup field with nothing to choose', async () => {
  server.use(http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])), http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])));
  renderRoute('/settings/issuance-defaults');
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
  const { user } = renderRoute('/settings/issuance-defaults');
  const mustStapleField = within(await screen.findByRole('group', { name: 'Must-Staple' }));
  expect(await mustStapleField.findByRole('switch', { name: 'Override Must-Staple' })).toBeChecked();

  await user.click(mustStapleField.getByRole('button', { name: 'Reset to inherited' }));
  // Before the save lands, `effective` still says 'org' with the old value
  // — showing that here (instead of "Inherited after save"/"Pending") would
  // be stale (review fix round 1, #3).
  expect(mustStapleField.getByText('Pending')).toBeInTheDocument();
  expect(mustStapleField.getByText('Inherited after save')).toBeInTheDocument();

  await user.click(screen.getByRole('button', { name: 'Save org defaults' }));
  await waitFor(() => expect(puts.org).toEqual({ ...allNull, mustStaple: null, reuseKey: true }));
  await waitFor(() => expect(mustStapleField.getByRole('button', { name: 'Default' })).toBeInTheDocument());
});

it('Global tab: unsaved fields show Default (not already Overridden), with the one-sentence copy and built-in effective value', async () => {
  const { user } = renderRoute('/settings/issuance-defaults');
  await user.click(await screen.findByRole('tab', { name: 'Global' }));
  expect(screen.getByText("Fields left as Default follow the server's built-in values.")).toBeInTheDocument();
  const keyTypeField = within(screen.getByRole('group', { name: 'Key type' }));
  expect(keyTypeField.getByRole('button', { name: 'Default' })).toBeInTheDocument();
  expect(keyTypeField.getByRole('switch', { name: 'Override Key type' })).not.toBeChecked();
  expect(keyTypeField.getByText('EC P-256')).toBeInTheDocument();
});

it('Global tab save: an untouched field is sent as explicit null, not the built-in display value', async () => {
  const { user } = renderRoute('/settings/issuance-defaults');
  await user.click(await screen.findByRole('tab', { name: 'Global' }));
  await user.click(await screen.findByRole('switch', { name: 'Override Must-Staple' }));
  await user.click(screen.getByRole('button', { name: 'Save global defaults' }));
  // Overriding Must-Staple seeds it from the built-in (false); every other
  // field the operator never touched is explicit null, not `value`'s
  // built-in-filled 'ec256'/33%/etc — the bug review fix round 1 #1 fixes.
  await waitFor(() => expect(puts.issuance_defaults).toEqual({ ...allNull, mustStaple: false }));
});

it('keeps the tab header wrapping at phone width', async () => {
  renderRoute('/settings/issuance-defaults');
  const tablist = await screen.findByRole('tablist');
  expect(tablist.parentElement?.className).toContain('flex-wrap');
});
