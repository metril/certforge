import { createHmac } from 'node:crypto';
import { adminApi, expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';
import { startSink, type SinkRequest } from './sink';

const SIGNING_SECRET = 'e2e-signing-secret-0123';

function deliveryFor(requests: SinkRequest[], kind: string): SinkRequest | undefined {
  return requests.filter((r) => r.headers['x-certforge-event'] === kind).at(-1);
}

test('channel CRUD with webhook test', async ({ page }) => {
  test.setTimeout(120_000);
  const sink = await startSink(E2E.sinkPort);
  try {
    await page.goto('/login');
    await signInLocal(page);
    await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

    await page.goto(`/o/${E2E.orgSlug}/alerts/channels`);
    await page.getByRole('button', { name: 'Add channel' }).click();
    const sheet = page.getByRole('dialog', { name: 'New channel' });
    await expect(sheet).toBeVisible();

    // The sheet auto-focuses its first tabbable element on open (Task 3's
    // ChannelTest "Send test" button is disabled on a new channel, so focus
    // lands on its own HelpTip button instead), same class of stray-tooltip
    // issue issuers.spec.ts's "CA kind switching" already works around —
    // focusing Name first (needed anyway) closes it via blur.
    await sheet.getByLabel('Name', { exact: true }).click();
    await sheet.getByLabel('Name', { exact: true }).fill('e2e-webhook');
    await sheet.getByRole('radio', { name: 'Webhook' }).click();
    await sheet.getByLabel('URL', { exact: true }).fill(`http://${E2E.sinkHost}:${E2E.sinkPort}/hook`);
    await sheet.getByLabel('Signing secret', { exact: true }).fill(SIGNING_SECRET);
    await sheet.getByRole('toolbar', { name: 'Certificates' }).getByRole('button', { name: 'Issued' }).click();
    await sheet.getByRole('button', { name: 'Save' }).click();
    await expect(sheet).toBeHidden();

    const table = page.getByRole('table', { name: 'Channels' });
    await expect(table.getByRole('row', { name: /^e2e-webhook/ })).toBeVisible();
    await snap(page, 'channels');

    // Reopen: the URL shows as stored (SecretInput never re-sends a secret
    // it didn't just receive fresh input for). Clicks the Name cell itself,
    // not the row's bounding-box center (which can land on the Enabled
    // switch column and toggle it instead of opening the sheet).
    await table.getByRole('row', { name: /^e2e-webhook/ }).getByText('e2e-webhook', { exact: true }).click();
    const edit = page.getByRole('dialog', { name: 'e2e-webhook' });
    await expect(edit).toBeVisible();
    // Both URL and Signing secret are stored secrets, so two "Stored"
    // badges render; asserting the first is enough to prove neither was
    // sent back with a fresh value.
    await expect(edit.getByText('Stored', { exact: true }).first()).toBeVisible();

    await edit.getByRole('button', { name: 'Send test' }).click();
    await expect(edit.getByText('Delivered')).toBeVisible({ timeout: 30_000 });
    await snap(page, 'channel-sheet');

    const delivery = deliveryFor(sink.requests, 'test');
    if (!delivery) throw new Error('sink received no test delivery');
    const wantSig = `sha256=${createHmac('sha256', SIGNING_SECRET).update(delivery.body).digest('hex')}`;
    expect(String(delivery.headers['x-certforge-signature'])).toBe(wantSig);

    // Browser Back with an unsaved edit asks first; Cancel keeps the draft.
    await edit.getByLabel('Name', { exact: true }).fill('e2e-webhook-renamed');
    await page.goBack();
    const discard = page.getByRole('dialog', { name: 'Discard changes?' });
    await expect(discard).toBeVisible();
    await discard.getByRole('button', { name: 'Cancel' }).click();
    await expect(discard).toBeHidden();
    await expect(edit).toBeVisible();
    await expect(edit.getByLabel('Name', { exact: true })).toHaveValue('e2e-webhook-renamed');
    await expect(page).toHaveURL(/edit=/);

    // Rename and save.
    await edit.getByRole('button', { name: 'Save' }).click();
    await expect(edit).toBeHidden();

    // Toggle Enabled off in the table.
    const renamedRow = table.getByRole('row', { name: /^e2e-webhook-renamed/ });
    await expect(renamedRow).toBeVisible();
    await renamedRow.getByRole('switch', { name: 'Enabled e2e-webhook-renamed' }).click();
    await expect(renamedRow.getByRole('switch', { name: 'Enabled e2e-webhook-renamed' })).not.toBeChecked();

    // Delete with confirm.
    await renamedRow.getByText('e2e-webhook-renamed', { exact: true }).click();
    const editRenamed = page.getByRole('dialog', { name: 'e2e-webhook-renamed' });
    await expect(editRenamed).toBeVisible();
    await editRenamed.getByRole('button', { name: 'Delete' }).click();
    const confirmDialog = page.getByRole('dialog', { name: 'Delete channel?' });
    await confirmDialog.getByRole('textbox').fill('e2e-webhook-renamed');
    await confirmDialog.getByRole('button', { name: 'Delete channel' }).click();
    await expect(confirmDialog).toBeHidden();
    await expect(table.getByRole('row', { name: /^e2e-webhook-renamed/ })).toHaveCount(0);
  } finally {
    await sink.close();
  }
});

test('monitor check', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/alerts/monitors`);
  await page.getByRole('button', { name: 'Add monitor' }).click();
  const sheet = page.getByRole('dialog', { name: 'New monitor' });
  await expect(sheet).toBeVisible();

  await sheet.getByLabel('Name', { exact: true }).click();
  await sheet.getByLabel('Name', { exact: true }).fill('e2e-listener');
  await sheet.getByLabel('Host', { exact: true }).fill('certforge');
  await sheet.getByLabel('Port', { exact: true }).fill('8443');
  await sheet.getByRole('radio', { name: '5 m', exact: true }).click();
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();

  const table = page.getByRole('table', { name: 'Monitors' });
  const row = table.getByRole('row', { name: /^e2e-listener/ });
  await expect(row).toBeVisible();
  // useCreateMonitor's own "Monitor created" toast (api/queries/monitors.ts)
  // auto-dismisses; waited out before snapping rather than raced against —
  // screens.ts's own setTheme falls back to a CSS-only flip once a sheet
  // covers the account menu trigger, which never reaches the Toaster's own
  // React `theme` state, so a toast still visible at that point would carry
  // over from whichever theme rendered it first, not the one being captured.
  await expect(page.getByText('Monitor created')).toBeHidden({ timeout: 6_000 });
  await snap(page, 'monitors');

  // Clicks the Name cell itself, not the row's bounding-box center (which
  // can land on the Check now button column and run it instead of opening
  // the sheet).
  await row.getByText('e2e-listener', { exact: true }).click();
  const edit = page.getByRole('dialog', { name: 'e2e-listener' });
  await expect(edit).toBeVisible();
  await edit.getByRole('button', { name: 'Check now' }).click();
  // The e2e Traefik :8443 default certificate is set up only by the Go e2e
  // (6a-facts.md), so this Playwright monitor targets the always-up agent
  // listener certforge:8443 instead and gets a deterministic Mismatch, never
  // Unknown (Deviations, "Playwright monitor").
  await expect(edit.getByText('Mismatch')).toBeVisible({ timeout: 30_000 });
  // Brief: "a state chip other than Unknown … and a fingerprint within
  // 30 s" — the fingerprint (CopyField's own <code>, the sheet's only one)
  // renders in the same batch as the state chip, so this is bounded by the
  // same 30 s wait above rather than its own separate timeout.
  const fingerprint = await edit.locator('code').textContent();
  expect(fingerprint?.trim()).toMatch(/^[0-9a-f]{64}$/);
  await expect(edit.getByText('Issuer')).toBeVisible();
  await expect(edit.getByText('Expires')).toBeVisible();
  await snap(page, 'monitor-sheet');
});

test('event log', async ({ page }) => {
  const { api, headers } = await adminApi();
  type Me = { orgs: { id: string; slug: string }[] };
  const me = (await (await api.get('/api/v1/auth/me', { headers })).json()) as Me;
  const org = me.orgs.find((o) => o.slug === E2E.orgSlug);
  if (!org) throw new Error(`org slug ${E2E.orgSlug} not found`);
  const channelRes = await api.post(`/api/v1/orgs/${org.id}/channels`, {
    headers,
    data: { name: 'e2e-event-log', type: 'webhook', config: { url: 'https://example.invalid/hook' } },
  });
  const channel = (await channelRes.json()) as { id: string };
  await api.post(`/api/v1/orgs/${org.id}/channels/${channel.id}/test`, { headers });
  await api.dispose();

  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/alerts/events`);
  await page.getByRole('combobox', { name: 'Kind' }).click();
  await page.getByRole('option', { name: 'Test', exact: true }).click();
  await page.keyboard.press('Escape');
  const list = page.getByRole('table', { name: 'Events' });
  await expect(list.getByText('Test', { exact: true }).first()).toBeVisible();
  // The deliveries cell is one summary chip per event; the channel name
  // lives in its popover.
  await expect(list.getByRole('button', { name: /^Deliveries: / }).first()).toBeVisible();
  await snap(page, 'events');
});

// Self-contained (same pre-flight ruling as issuers.spec.ts's own 375 px
// test and clients.spec.ts's own): seeds its own channel and monitor
// through the admin API, under distinct names, before the page ever signs
// in (a page sign-in revokes this API session's own login). Alerts is new
// in 6B and has never been checked at 375 px; Integrations and Backup were
// last checked by issuers.spec.ts (5B, before 6B added Email, Notifications,
// Prometheus and the backup schedule form), so both are re-checked here too.
test('alerts and integrations/backup screens do not scroll sideways at 375 px', async ({ page }) => {
  const { api, headers } = await adminApi();
  type Me = { orgs: { id: string; slug: string }[] };
  const me = (await (await api.get('/api/v1/auth/me', { headers })).json()) as Me;
  const org = me.orgs.find((o) => o.slug === E2E.orgSlug);
  if (!org) throw new Error(`org slug ${E2E.orgSlug} not found`);
  await api.post(`/api/v1/orgs/${org.id}/channels`, {
    headers,
    data: { name: 'e2e-webhook-375', type: 'webhook', config: { url: 'https://example.invalid/hook' } },
  });
  await api.post(`/api/v1/orgs/${org.id}/monitors`, { headers, data: { name: 'e2e-listener-375', host: 'certforge', port: 8443 } });
  await api.dispose();

  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.setViewportSize({ width: 375, height: 812 });
  const noScroll = async () => expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);

  await page.goto(`/o/${E2E.orgSlug}/alerts/channels`);
  await expect(page.getByRole('heading', { level: 1, name: 'Alerts' })).toBeVisible();
  await noScroll();
  // Below `md`, the channels/monitors lists render as stacked cards, not a
  // table, so this targets the row/card's own name text either way.
  await page.getByText('e2e-webhook-375', { exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'e2e-webhook-375' })).toBeVisible();
  await noScroll();
  await page.keyboard.press('Escape');

  await page.goto(`/o/${E2E.orgSlug}/alerts/monitors`);
  await noScroll();
  await page.getByText('e2e-listener-375', { exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'e2e-listener-375' })).toBeVisible();
  await noScroll();
  await page.keyboard.press('Escape');

  await page.goto(`/o/${E2E.orgSlug}/alerts/events`);
  await noScroll();

  await page.goto('/settings/integrations');
  await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible();
  await noScroll();

  await page.goto('/settings/backup');
  await noScroll();
});

// Real data has long channel names, a global event with a long resource name
// and a very long summary; a fixed-layout table must clip them, never scroll.
test('events table does not scroll sideways with realistic data', async ({ page }) => {
  const at = new Date().toISOString();
  const dl = (id: string, status: 'pending' | 'delivered' | 'failed', name: string) => ({
    channelId: id, channelName: name, status, attempts: status === 'failed' ? 3 : 1, lastError: status === 'failed' ? 'connection refused by the remote endpoint' : null, deliveredAt: status === 'delivered' ? at : null,
  });
  const ev = (id: string, o: Record<string, unknown>) => ({
    id, kind: 'cert.issued', at, orgId: 'stub-org', severity: 'info', resource: { type: 'certificate', id: 'c-1', name: 'www.example.com' }, summary: 'www.example.com issued', details: {}, deliveries: [], ...o,
  });
  const items = [
    ev('e1', {
      deliveries: [
        dl('c1', 'delivered', 'ops-pager-production-primary'),
        dl('c2', 'failed', 'ops-pager-production-secondary'),
        dl('c3', 'pending', 'ops-chat-production-primary'),
        dl('c4', 'delivered', 'ops-mail-production-primary'),
      ],
    }),
    ev('e2', { kind: 'backup.completed', orgId: null, resource: { type: 'backup', id: 'b-1', name: 'certforge-backup-20260101T000000Z-with-a-long-name.cfbak' }, summary: 'Backup completed' }),
    ev('e3', { kind: 'cert.expiring', severity: 'critical', summary: 'www.example.com expires in 2 days', deliveries: [dl('c1', 'delivered', 'ops-pager-production-primary')] }),
    ev('e4', { summary: 'No channel matched', deliveries: [] }),
    ev('e5', { summary: 'x'.repeat(300) }),
    ev('e6', { kind: 'cert.expired', severity: 'critical', summary: 'api.example.com expired', deliveries: [dl('c1', 'pending', 'ops-pager-production-primary')] }),
  ];
  await page.route(/\/api\/v1\/orgs\/[^/]+\/events(\?.*)?$/, (route) =>
    route.request().method() === 'GET' ? route.fulfill({ json: { items, nextCursor: null } }) : route.continue(),
  );

  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  for (const width of [1024, 1280, 1440, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`/o/${E2E.orgSlug}/alerts/events`);
    const table = page.getByRole('table', { name: 'Events' });
    await expect(table.getByRole('row')).toHaveCount(items.length + 1);
    const kind = table.locator('td span', { hasText: /^Certificate expiring$/ }).first();
    await expect(kind).toBeVisible();
    const m = await page.evaluate(() => {
      const c = document.querySelector('[data-slot=table-container]')!;
      const d = document.scrollingElement!;
      return { cScroll: c.scrollWidth, cClient: c.clientWidth, dScroll: d.scrollWidth, dClient: d.clientWidth };
    });
    expect(m.cScroll, `table container at ${width}`).toBeLessThanOrEqual(m.cClient);
    expect(m.dScroll, `document at ${width}`).toBeLessThanOrEqual(m.dClient);
    expect(await kind.evaluate((el) => el.scrollWidth <= el.clientWidth), `Kind cell clipped at ${width}`).toBe(true);
    if (width === 1280) await snap(page, 'events-realistic');
  }
});
