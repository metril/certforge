import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeAction, makeActionGroup, makeTarget, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { argvErrors } from '@/forms/widgets/ArgvField';

describe('argvErrors', () => {
  it('needs an absolute, already-clean executable path', () => {
    expect(argvErrors([''])).toEqual(['Enter the executable path.']);
    expect(argvErrors(['nginx'])).toEqual(['Use an absolute path.']);
    expect(argvErrors(['/'])).toEqual(['Use a clean path: no . or .. segments, no trailing or repeated slash.']);
    expect(argvErrors(['/usr/sbin/../nginx'])).toEqual(['Use a clean path: no . or .. segments, no trailing or repeated slash.']);
    expect(argvErrors(['/usr/sbin/nginx/'])).toEqual(['Use a clean path: no . or .. segments, no trailing or repeated slash.']);
    expect(argvErrors(['/usr//sbin/nginx'])).toEqual(['Use a clean path: no . or .. segments, no trailing or repeated slash.']);
    expect(argvErrors(['/usr/sbin/nginx'])).toEqual([null]);
  });

  it('accepts spaces and empty strings in arguments, unlike the executable', () => {
    // The server never runs a hook through a shell, so an argument's own
    // spaces or emptiness are none of the client's business.
    expect(argvErrors(['/usr/sbin/nginx -s reload'])).toEqual([null]);
    expect(argvErrors(['/usr/sbin/nginx', '', '-s'])).toEqual([null, null, null]);
    expect(argvErrors(['/usr/sbin/nginx', 'a b'])).toEqual([null, null]);
  });

  it('caps every argument at 4096 bytes and refuses an embedded NUL', () => {
    const long = '/' + 'a'.repeat(4096);
    expect(argvErrors([long])).toEqual(['Keep it to at most 4096 bytes.']);
    expect(argvErrors(['/usr/sbin/nginx', 'x'.repeat(4097)])).toEqual([null, 'Keep it to at most 4096 bytes.']);
    expect(argvErrors(['/usr/sbin/nginx\0'])).toEqual(['Remove the embedded NUL character.']);
  });
});

const A1 = '11111111-1111-4111-8111-111111111111';
const A2 = '22222222-2222-4222-8222-222222222222';
const T_SSH = '33333333-3333-4333-8333-333333333333';
const T_PIKVM = '44444444-4444-4444-8444-444444444444';
const T_TRAEFIK = '55555555-5555-4555-8555-555555555555';

let posted: unknown;
let patched: unknown;
let deleted: string[];
let postedGroup: unknown;

beforeEach(() => {
  posted = undefined;
  patched = undefined;
  postedGroup = undefined;
  deleted = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/actions'), () =>
      HttpResponse.json({
        items: [
          makeAction({ id: A1, grantCount: 1 }),
          makeAction({ id: A2, name: 'verify site', kind: 'verify_tls', phase: 'post_deploy', runsOn: 'server', config: { host: 'a.example.com', port: 443 }, optional: true, timeoutSeconds: 30 }),
        ],
      }),
    ),
    http.get(url('/orgs/org-1/action-groups'), () => HttpResponse.json({ items: [makeActionGroup({ actionIds: [A1, A2], grantCount: 2 })] })),
    http.get(url('/orgs/org-1/deploy-targets'), () =>
      HttpResponse.json({
        items: [
          makeTarget({ id: T_SSH, name: 'bastion', type: 'ssh', runsOn: 'server' }),
          makeTarget({ id: T_PIKVM, name: 'kvm', type: 'pikvm', runsOn: 'server' }),
          makeTarget({ id: T_TRAEFIK, name: 'edge traefik', type: 'traefik' }),
        ],
      }),
    ),
    http.post(url('/orgs/org-1/actions'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeAction({ id: 'a-3' }), { status: 201 });
    }),
    http.patch(url('/orgs/org-1/actions/:id'), async ({ request }) => {
      patched = await request.json();
      return HttpResponse.json(makeAction());
    }),
    http.delete(url('/orgs/org-1/actions/:id'), ({ params }) => {
      deleted.push(params.id as string);
      return new HttpResponse(null, { status: 204 });
    }),
    http.post(url('/orgs/org-1/action-groups'), async ({ request }) => {
      postedGroup = await request.json();
      return HttpResponse.json(makeActionGroup({ id: 'ag-2' }), { status: 201 });
    }),
  );
});

it('lists actions with kind, phase, runs-on, timeout and used-by', async () => {
  renderRoute('/o/acme/delivery/actions');
  const table = await screen.findByRole('table', { name: 'Actions' });
  const row = within(table).getByText('reload nginx').closest('tr')!;
  for (const text of ['Run command (agent)', 'Post', 'Agent', '60 s', '1 grant']) expect(within(row).getByText(text)).toBeInTheDocument();
  const verify = within(table).getByText('verify site').closest('tr')!;
  for (const text of ['Optional', 'Server', '30 s']) expect(within(verify).getByText(text)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Delete reload nginx' })).toHaveAttribute('aria-disabled', 'true');
});

it('creates a pre-deploy exec action from argv rows', async () => {
  const { user } = renderRoute('/o/acme/delivery/actions');
  await user.click(await screen.findByRole('button', { name: 'New action' }));
  const sheet = await screen.findByRole('dialog', { name: 'New action' });
  await user.type(within(sheet).getByLabelText('Name'), 'test config');
  await user.click(await within(sheet).findByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /Run command \(agent\)/ }));
  await user.click(within(sheet).getByRole('radio', { name: 'Pre-deploy' }));
  await user.type(within(sheet).getByLabelText('Executable'), '/usr/sbin/nginx');
  await user.click(within(sheet).getByRole('button', { name: 'Add argument' }));
  await user.type(within(sheet).getByLabelText('Argument 1'), '-t');
  await user.clear(within(sheet).getByLabelText('Timeout'));
  await user.type(within(sheet).getByLabelText('Timeout'), '30');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(posted).toEqual({ name: 'test config', kind: 'exec', phase: 'pre_deploy', config: { argv: ['/usr/sbin/nginx', '-t'] }, timeoutSeconds: 30, optional: false }),
  );
});

it('creates an http action and prefills the phase from the kind hint', async () => {
  const { user } = renderRoute('/o/acme/delivery/actions?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New action' });
  await user.type(within(sheet).getByLabelText('Name'), 'ping');
  await user.click(within(sheet).getByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /HTTP request/ }));
  expect(within(sheet).getByRole('radio', { name: 'Post-deploy' })).toBeChecked();
  await user.click(await within(sheet).findByRole('radio', { name: 'POST' }));
  await user.type(within(sheet).getByLabelText('URL'), 'https://hooks.example.com/x');
  await user.click(within(sheet).getByRole('switch', { name: 'Optional' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ name: 'ping', kind: 'http', phase: 'post_deploy', optional: true, config: { method: 'POST', url: 'https://hooks.example.com/x' } }));
});

it('offers only deploy targets of the types the kind accepts', async () => {
  const { user } = renderRoute('/o/acme/delivery/actions?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New action' });
  await user.type(within(sheet).getByLabelText('Name'), 'reload');
  await user.click(within(sheet).getByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /SSH command/ }));
  await user.click(await within(sheet).findByRole('combobox', { name: 'Target' }));
  expect(await screen.findByRole('option', { name: /bastion/ })).toBeInTheDocument();
  expect(screen.getByRole('option', { name: /kvm/ })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: /edge traefik/ })).not.toBeInTheDocument();
  await user.click(screen.getByRole('option', { name: /bastion/ }));
  await user.type(within(sheet).getByLabelText('Command'), 'systemctl reload nginx');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ kind: 'ssh', config: { targetId: T_SSH, command: 'systemctl reload nginx' } }));
});

it('sends __unchanged__ for a stored secret that was not touched', async () => {
  server.use(
    http.get(url('/orgs/org-1/actions'), () =>
      HttpResponse.json({ items: [makeAction({ id: A1, name: 'webhook', kind: 'http', runsOn: 'server', config: { method: 'POST', url: 'https://x.example.com' }, secretKeys: ['secretHeaders'] })] }),
    ),
  );
  const { user } = renderRoute(`/o/acme/delivery/actions?edit=${A1}`);
  const sheet = await screen.findByRole('dialog', { name: 'Edit webhook' });
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ kind: 'http', config: { method: 'POST', url: 'https://x.example.com', secretHeaders: '__unchanged__' } }));
});

it('edits an action with a PATCH carrying the full body', async () => {
  const { user } = renderRoute(`/o/acme/delivery/actions?edit=${A1}`);
  const sheet = await screen.findByRole('dialog', { name: 'Edit reload nginx' });
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toEqual({ name: 'reload nginx', kind: 'exec', phase: 'post_deploy', config: { argv: ['/usr/sbin/nginx', '-s', 'reload'] }, timeoutSeconds: 60, optional: false }));
});

it('refuses a relative executable and a bad timeout', async () => {
  const { user } = renderRoute('/o/acme/delivery/actions?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New action' });
  await user.type(within(sheet).getByLabelText('Name'), 'bad');
  await user.click(within(sheet).getByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /Run command \(agent\)/ }));
  await user.type(within(sheet).getByLabelText('Executable'), 'nginx');
  await user.clear(within(sheet).getByLabelText('Timeout'));
  await user.type(within(sheet).getByLabelText('Timeout'), '0');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(within(sheet).getByText('Use an absolute path.')).toBeInTheDocument();
  expect(within(sheet).getByText('Use 1 to 3600 seconds.')).toBeInTheDocument();
  expect(posted).toBeUndefined();
});

it('deletes an unused action via the confirm dialog', async () => {
  const { user } = renderRoute('/o/acme/delivery/actions');
  await screen.findByRole('table', { name: 'Actions' });
  await user.click(screen.getByRole('button', { name: 'Delete verify site' }));
  await user.type(screen.getByLabelText(/to confirm/), 'verify site');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(deleted).toEqual([A2]));
});

it('shows a 409 (still used) inside the delete dialog', async () => {
  server.use(http.delete(url('/orgs/org-1/actions/:id'), () => problem(409, 'Used by group web reload.')));
  const { user } = renderRoute('/o/acme/delivery/actions');
  await user.click(await screen.findByRole('button', { name: 'Delete verify site' }));
  await user.type(screen.getByLabelText(/to confirm/), 'verify site');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  expect(await within(screen.getByRole('dialog')).findByText('Used by group web reload.')).toBeInTheDocument();
});

it('puts a name-conflict 409 under Name and any other error in the page alert', async () => {
  server.use(http.post(url('/orgs/org-1/actions'), () => problem(409, 'An action named "reload nginx" already exists in this org.')));
  const { user } = renderRoute('/o/acme/delivery/actions?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New action' });
  await user.type(within(sheet).getByLabelText('Name'), 'reload nginx');
  await user.click(within(sheet).getByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /Run command \(agent\)/ }));
  await user.type(within(sheet).getByLabelText('Executable'), '/usr/sbin/nginx');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByText('An action named "reload nginx" already exists in this org.')).toBeInTheDocument();
  expect(within(sheet).getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true');

  server.use(http.post(url('/orgs/org-1/actions'), () => problem(500, 'boom')));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  const alert = (await within(sheet).findByText('boom')).closest('[role="alert"]');
  expect(alert).toBeInTheDocument();
  expect(within(sheet).getByLabelText('Name')).not.toHaveAttribute('aria-invalid', 'true');
});

it('lists groups and builds an ordered group', async () => {
  const { user } = renderRoute('/o/acme/delivery/actions?tab=groups');
  const table = await screen.findByRole('table', { name: 'Action groups' });
  expect(within(table).getByText((_, el) => el?.tagName === 'TD' && el.textContent === 'reload nginx → verify site')).toBeInTheDocument();
  expect(within(table).getByText('2 grants')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'New group' }));
  const sheet = await screen.findByRole('dialog', { name: 'New action group' });
  await user.type(within(sheet).getByLabelText('Name'), 'reload then verify');
  for (const n of ['reload nginx', 'verify site']) {
    await user.click(within(sheet).getByRole('combobox', { name: 'Add action' }));
    await user.click(await screen.findByRole('option', { name: new RegExp(n) }));
  }
  await user.click(within(sheet).getByRole('button', { name: 'Move verify site up' }));
  const items = within(within(sheet).getByRole('list', { name: 'Actions in order' })).getAllByRole('listitem');
  expect(items[0]).toHaveTextContent('verify site');
  await user.click(within(sheet).getByRole('button', { name: 'Remove reload nginx' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(postedGroup).toEqual({ name: 'reload then verify', actionIds: [A2] }));
});

it('validates a restart target and picks a notification channel', async () => {
  server.use(http.get(url('/orgs/org-1/channels'), () => HttpResponse.json([{ id: '66666666-6666-4666-8666-666666666666', orgId: 'org-1', name: 'ops chat', type: 'discord' }])));
  const { user } = renderRoute('/o/acme/delivery/actions?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New action' });
  await user.type(within(sheet).getByLabelText('Name'), 'restart web');
  await user.click(within(sheet).getByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /Restart service \(agent\)/ }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(within(sheet).getByText('Use docker:<container> or systemd:<unit>.')).toBeInTheDocument();
  expect(posted).toBeUndefined();
  await user.click(within(sheet).getByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /Send notification/ }));
  await user.click(await within(sheet).findByRole('combobox', { name: 'Channel' }));
  await user.click(await screen.findByRole('option', { name: /ops chat/ }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ kind: 'notify', config: { channelId: '66666666-6666-4666-8666-666666666666' } }));
});

it('hides Optional for agent-run kinds and resets it when switching to one', async () => {
  const { user } = renderRoute('/o/acme/delivery/actions?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New action' });
  await user.type(within(sheet).getByLabelText('Name'), 'x');
  await user.click(within(sheet).getByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /HTTP request/ }));
  await user.click(within(sheet).getByRole('switch', { name: 'Optional' }));
  await user.click(within(sheet).getByRole('combobox', { name: 'Kind' }));
  await user.click(await screen.findByRole('option', { name: /Run command \(agent\)/ }));
  expect(within(sheet).queryByRole('switch', { name: 'Optional' })).not.toBeInTheDocument();
  await user.type(within(sheet).getByLabelText('Executable'), '/bin/true');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ kind: 'exec', optional: false }));
});
