import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { Channel, ChannelInput } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, makeChannel, meWith, metaNotifiers, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let channels: Channel[];
let posted: ChannelInput | undefined;
let put: ChannelInput | undefined;
let deletedId: string | undefined;
let tested: string | undefined;
let testResult: { status: 'delivered' | 'failed'; error?: string; durationMs: number };

beforeEach(() => {
  channels = [];
  posted = put = deletedId = tested = undefined;
  testResult = { status: 'delivered', durationMs: 42 };
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [], notifiers: metaNotifiers, signers: [] })),
    http.get(url('/orgs/:orgId/channels'), () => HttpResponse.json(channels)),
    http.post(url('/orgs/:orgId/channels'), async ({ request }) => {
      posted = (await request.json()) as ChannelInput;
      return HttpResponse.json(makeChannel({ id: 'ch-new', ...posted, config: posted.config, storedSecrets: [] }), { status: 201 });
    }),
    http.patch(url('/orgs/:orgId/channels/:id'), async ({ request, params }) => {
      put = (await request.json()) as ChannelInput;
      const existing = channels.find((c) => c.id === params.id)!;
      return HttpResponse.json({ ...existing, ...put });
    }),
    http.delete(url('/orgs/:orgId/channels/:id'), ({ params }) => {
      deletedId = params.id as string;
      return new HttpResponse(null, { status: 204 });
    }),
    http.post(url('/orgs/:orgId/channels/:id/test'), ({ params }) => {
      tested = params.id as string;
      return HttpResponse.json(testResult);
    }),
  );
});

it('type switch swaps schema form', async () => {
  const { user } = renderRoute('/o/acme/alerts/channels?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New channel' });
  expect(await within(sheet).findByLabelText('URL')).toBeInTheDocument();
  await user.click(within(sheet).getByRole('radio', { name: 'Discord' }));
  expect(within(sheet).queryByLabelText('URL')).not.toBeInTheDocument();
  expect(within(sheet).getByLabelText('Webhook URL')).toBeInTheDocument();
});

it('type locked on edit', async () => {
  channels = [makeChannel()];
  renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  expect(within(sheet).getByRole('radio', { name: 'Webhook' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'Discord' })).toBeDisabled();
});

it('per-type draft kept when switching back', async () => {
  const { user } = renderRoute('/o/acme/alerts/channels?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New channel' });
  await user.type(await within(sheet).findByLabelText('URL'), 'https://hooks.example.com/a');
  await user.click(within(sheet).getByRole('radio', { name: 'Discord' }));
  await user.click(within(sheet).getByRole('radio', { name: 'Webhook' }));
  expect(within(sheet).getByLabelText('URL')).toHaveValue('https://hooks.example.com/a');
});

it('all events chip clears selection', async () => {
  channels = [makeChannel({ events: ['cert.issued'] })];
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  const all = within(sheet).getByRole('button', { name: 'All events' });
  expect(all).toHaveAttribute('aria-pressed', 'false');
  await user.click(all);
  expect(all).toHaveAttribute('aria-pressed', 'true');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toBeDefined());
  expect(put!.events).toEqual([]);
});

it('grouped chips send kinds in enum order', async () => {
  channels = [makeChannel()];
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  // Click a later-group kind before an earlier-group one; the emitted
  // array must still follow EventKind enum order, not click order.
  // ("Failed" is deploy.failed's short label in the Deployments group — the
  // same short label backup.failed uses in Backups, so the group scopes it.)
  await user.click(within(within(sheet).getByRole('toolbar', { name: 'Deployments' })).getByRole('button', { name: 'Failed' }));
  await user.click(within(within(sheet).getByRole('toolbar', { name: 'Certificates' })).getByRole('button', { name: 'Issued' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toBeDefined());
  expect(put!.events).toEqual(['cert.issued', 'deploy.failed']);
});

it('min severity segmented', async () => {
  channels = [makeChannel()];
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  await user.click(within(sheet).getByRole('button', { name: 'Advanced' }));
  await user.click(within(sheet).getByRole('radio', { name: 'Critical' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toBeDefined());
  expect(put!.minSeverity).toBe('critical');
});

it('all orgs disabled for non-admin', async () => {
  channels = [makeChannel()];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  await user.click(within(sheet).getByRole('button', { name: 'Advanced' }));
  const sw = within(sheet).getByRole('switch', { name: 'All orgs' });
  expect(sw).toBeDisabled();
  await user.hover(sw);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs a global admin');
});

it('create posts ChannelInput', async () => {
  const { router, user } = renderRoute('/o/acme/alerts/channels?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New channel' });
  await user.type(within(sheet).getByLabelText('Name'), 'ops-hook');
  await user.type(within(sheet).getByLabelText('URL'), 'https://hooks.example.com/a');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(posted).toEqual({
      name: 'ops-hook',
      type: 'webhook',
      config: { url: 'https://hooks.example.com/a' },
      events: [],
      minSeverity: 'info',
      allOrgs: false,
      enabled: true,
    }),
  );
  await waitFor(() => expect(router.state.location.search).toEqual({}));
});

it('edit sends sentinel for stored secrets', async () => {
  channels = [makeChannel({ storedSecrets: ['url'], config: {} })];
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toBeDefined());
  expect(put!.config).toEqual({ url: '__unchanged__' });
});

// Batch 1 review: `withSecretSentinels` (forms/uiSchema.ts) fills the
// sentinel for ANY empty value, including SecretInput's own Remove (which
// emits ''), so a Remove was silently turned back into __unchanged__ (the
// stored secret's old value) instead of clearing it.
it("remove stored secret sends '' and marks dirty", async () => {
  channels = [makeChannel({ storedSecrets: ['url'], config: {} })];
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  expect(await within(sheet).findByRole('button', { name: 'Send test' })).toBeEnabled();
  await user.click(within(sheet).getByRole('button', { name: 'Remove URL' }));
  // Query fresh: going from allowed to disabled swaps PermissionTip's own
  // wrapper (fragment -> Tooltip), remounting the button under a new node.
  expect(within(sheet).getByRole('button', { name: 'Send test' })).toBeDisabled();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toBeDefined());
  expect(put!.config).toEqual({ url: '' });
});

// W1: the webhook signingSecret has minLength 16; Remove's '' must not be
// blocked by it.
it("remove a stored secret that has minLength saves '' ", async () => {
  channels = [makeChannel({ storedSecrets: ['url', 'signingSecret'] })];
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  await user.click(await within(sheet).findByRole('button', { name: 'Remove Signing secret' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toBeDefined());
  expect(put!.config).toMatchObject({ signingSecret: '' });
});

it('re-enter secret maps to token field', async () => {
  channels = [makeChannel({ id: 'ch-ntfy', name: 'push', type: 'ntfy', storedSecrets: ['token'], config: { server: 'https://ntfy.sh', topic: 'certforge' } })];
  server.use(http.patch(url('/orgs/:orgId/channels/:id'), () => problem(422, 'Invalid config: re-enter the secret')));
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-ntfy');
  const sheet = await screen.findByRole('dialog', { name: 'push' });
  const serverField = await within(sheet).findByLabelText('Server');
  await user.clear(serverField);
  await user.type(serverField, 'https://ntfy.example.com');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByText(/re-enter the secret/)).toBeInTheDocument();
});

it('headers add and remove rows', async () => {
  const { user } = renderRoute('/o/acme/alerts/channels?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New channel' });
  await user.click(await within(sheet).findByRole('button', { name: 'Add header' }));
  await user.type(within(sheet).getByLabelText('Header 1 name'), 'X-Remove');
  await user.type(within(sheet).getByLabelText('Header 1 value'), 'gone');
  await user.click(within(sheet).getByRole('button', { name: 'Add header' }));
  await user.type(within(sheet).getByLabelText('Header 2 name'), 'X-Env');
  await user.type(within(sheet).getByLabelText('Header 2 value'), 'prod');
  // Removing the first row drops it from the payload; the second stays.
  await user.click(within(sheet).getByRole('button', { name: 'Remove header 1' }));
  await user.type(within(sheet).getByLabelText('URL'), 'https://hooks.example.com/a');
  await user.type(within(sheet).getByLabelText('Name'), 'ops-hook');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toBeDefined());
  expect(posted!.config).toMatchObject({ headers: { 'X-Env': 'prod' } });
  expect(posted!.config).not.toHaveProperty('headers.X-Remove');
});

it('send test delivered chip with duration', async () => {
  channels = [makeChannel()];
  testResult = { status: 'delivered', durationMs: 88 };
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  await user.click(within(sheet).getByRole('button', { name: 'Send test' }));
  expect(await within(sheet).findByText('Delivered')).toBeInTheDocument();
  expect(within(sheet).getByText('88 ms')).toBeInTheDocument();
  expect(tested).toBe('ch-1');
});

it('send test failed shows error', async () => {
  channels = [makeChannel()];
  testResult = { status: 'failed', error: 'connection refused', durationMs: 10_000 };
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  const sendTest = within(sheet).getByRole('button', { name: 'Send test' });
  await user.click(sendTest);
  const testRow = sendTest.closest('div')!;
  expect(await within(testRow).findByText('Failed')).toBeInTheDocument();
  expect(within(testRow).getByText('connection refused')).toBeInTheDocument();
});

it('send test disabled while dirty', async () => {
  channels = [makeChannel()];
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  expect(within(sheet).getByRole('button', { name: 'Send test' })).toBeEnabled();
  await user.type(within(sheet).getByLabelText('Name'), '!');
  // Query fresh: going from allowed to disabled swaps PermissionTip's own
  // wrapper (fragment -> Tooltip), remounting the button under a new node.
  const sendTest = within(sheet).getByRole('button', { name: 'Send test' });
  expect(sendTest).toBeDisabled();
  // Batch 1 review: `PermissionTip allowed={canWrite}` (ignoring dirty)
  // returned bare children whenever the caller could write, so the
  // disabled-while-dirty button had no explaining tooltip at all.
  await user.hover(sendTest);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Save your changes first');
});

it('send test disabled for new channel', async () => {
  renderRoute('/o/acme/alerts/channels?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New channel' });
  expect(within(sheet).getByRole('button', { name: 'Send test' })).toBeDisabled();
});

it('delete confirms', async () => {
  channels = [makeChannel()];
  const { user, router } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  await user.click(within(sheet).getByRole('button', { name: 'Delete' }));
  const dialog = await screen.findByRole('dialog', { name: 'Delete channel?' });
  await user.type(within(dialog).getByLabelText(/Type/), 'ops-webhook');
  await user.click(within(dialog).getByRole('button', { name: 'Delete channel' }));
  await waitFor(() => expect(deletedId).toBe('ch-1'));
  await waitFor(() => expect(router.state.location.search).toEqual({}));
});

it('channel secrets not cached', async () => {
  channels = [makeChannel({ storedSecrets: [] })];
  const { user, queryClient, router } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  await user.type(await within(sheet).findByLabelText('URL'), 'https://hooks.example.com/s3cr3t-token');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toBeDefined());
  await waitFor(() => expect(router.state.location.search).toEqual({}));

  // Reopen the same channel and run Send test too — neither the save nor
  // the test result should ever put the secret in a query or mutation cache
  // entry (Save/Send test are direct calls, and the server never echoes a
  // secret back on GET).
  await router.navigate({ to: '/o/$org/alerts/channels', params: { org: 'acme' }, search: { edit: 'ch-1' } });
  const sheet2 = await screen.findByRole('dialog', { name: 'ops-webhook' });
  await user.click(within(sheet2).getByRole('button', { name: 'Send test' }));
  await waitFor(() => expect(tested).toBe('ch-1'));

  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  const cached = JSON.stringify(queryClient.getQueryCache().getAll().map((q) => q.state.data));
  expect(cached).not.toContain('s3cr3t-token');
});

it('shows Enabled outside the collapsed Advanced section', async () => {
  channels = [makeChannel()];
  renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  expect(within(sheet).getByRole('switch', { name: 'Enabled' })).toBeVisible();
  expect(within(sheet).getByRole('button', { name: 'Advanced' })).toHaveAttribute('aria-expanded', 'false');
});

it('read-only without alerts:write makes every field non-editable', async () => {
  channels = [makeChannel()];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/alerts/channels?edit=ch-1');
  const sheet = await screen.findByRole('dialog', { name: 'ops-webhook' });
  expect(within(sheet).getByLabelText('Name')).toBeDisabled();
  await within(sheet).findByRole('button', { name: 'Add header' }).then((b) => expect(b).toBeDisabled());
  expect(within(sheet).getByRole('button', { name: 'All events' })).toBeDisabled();
  expect(within(sheet).getByRole('switch', { name: 'Enabled' })).toBeDisabled();
  await user.click(within(sheet).getByRole('button', { name: 'Advanced' }));
  expect(within(sheet).getByRole('radio', { name: 'Critical' })).toBeDisabled();
});

it('duplicate header names (case-insensitive) show an error and block save', async () => {
  const { user } = renderRoute('/o/acme/alerts/channels?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New channel' });
  await user.type(await within(sheet).findByLabelText('Name'), 'ops');
  await user.type(within(sheet).getByLabelText('URL'), 'https://hooks.example.com/a');
  await user.click(within(sheet).getByRole('button', { name: 'Add header' }));
  await user.type(within(sheet).getByLabelText('Header 1 name'), 'X-Env');
  await user.click(within(sheet).getByRole('button', { name: 'Add header' }));
  await user.type(within(sheet).getByLabelText('Header 2 name'), 'x-env');
  expect(await within(sheet).findByText(/Duplicate header name/)).toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await new Promise((r) => setTimeout(r, 100));
  expect(posted).toBeUndefined();
  await user.clear(within(sheet).getByLabelText('Header 2 name'));
  await user.type(within(sheet).getByLabelText('Header 2 name'), 'X-Other');
  expect(within(sheet).queryByText(/Duplicate header name/)).not.toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toBeDefined());
});
