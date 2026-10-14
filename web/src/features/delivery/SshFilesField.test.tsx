import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeLayout, makeTarget, problem, sshSchema, traefikSchema, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let patched: unknown;
let files: Array<Record<string, string>>;

beforeEach(() => {
  patched = undefined;
  files = [
    { path: '/etc/ssl/a.pem', content: 'fullchain', mode: '0644' },
    { path: '/etc/ssl/a.key', content: 'key', mode: '0600' },
  ];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, sshSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () =>
      HttpResponse.json({
        items: [makeTarget({ id: 't-ssh', name: 'box', type: 'ssh', runsOn: 'server', config: { host: 'h.lan', port: 22, username: 'root', hostKey: 'ssh-ed25519 AAAA', files } })],
      }),
    ),
    http.get(url('/orgs/org-1/deploy-credentials'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/layouts'), () =>
      HttpResponse.json({ items: [makeLayout({ files: [{ path: '/x/haproxy.pem', format: 'pem', parts: ['fullchain'], owner: 'root', group: 'root', mode: '0640' }] })] }),
    ),
    http.patch(url('/orgs/org-1/deploy-targets/:id'), async ({ request }) => {
      patched = await request.json();
      return HttpResponse.json(makeTarget());
    }),
  );
});

async function open() {
  const r = renderRoute('/o/acme/delivery/targets/t-ssh/edit');
  await screen.findByRole('heading', { name: 'Edit box' });
  const sheet = document.body;
  await within(sheet).findByLabelText('File 1 remote path');
  return { ...r, sheet };
}

it('renders a row per configured file; Add appends a row with mode 0644; Remove disabled at one row', async () => {
  const { user, sheet } = await open();
  expect(within(sheet).getByLabelText('File 2 remote path')).toHaveValue('/etc/ssl/a.key');
  expect(within(sheet).getByLabelText('File 2 mode')).toHaveValue('0600');
  await user.click(within(sheet).getByRole('button', { name: 'Add file' }));
  expect(within(sheet).getByLabelText('File 3 mode')).toHaveValue('0644');
  await user.click(within(sheet).getByRole('button', { name: 'Remove file 3' }));
  await user.click(within(sheet).getByRole('button', { name: 'Remove file 2' }));
  expect(within(sheet).getByRole('button', { name: 'Remove file 1' })).toHaveAttribute('aria-disabled', 'true');
});

it('content suggestions include layout file base names', async () => {
  const { user, sheet } = await open();
  await user.click(within(sheet).getByRole('combobox', { name: 'File 1 content' }));
  expect(await screen.findByRole('option', { name: /haproxy\.pem/ })).toBeInTheDocument();
  expect(screen.getByRole('option', { name: /bundle/ })).toBeInTheDocument();
});

it('shows the key badge for key, bundle and custom content but not fullchain', async () => {
  const { user, sheet } = await open();
  const badges = () => within(sheet).queryAllByLabelText('Needs the private key');
  expect(badges()).toHaveLength(1);
  await user.click(within(sheet).getByRole('combobox', { name: 'File 1 content' }));
  await user.click(await screen.findByRole('option', { name: /bundle/ }));
  expect(badges()).toHaveLength(2);
  await user.click(within(sheet).getByRole('combobox', { name: 'File 2 content' }));
  await user.click(await screen.findByRole('option', { name: /^fullchain/ }));
  expect(badges()).toHaveLength(1);
});

it('a server files[1].path error marks row 2 path invalid', async () => {
  server.use(http.patch(url('/orgs/org-1/deploy-targets/:id'), () => problem(422, 'files[1].path: must be an absolute path')));
  const { user, sheet } = await open();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(within(sheet).getByLabelText('File 2 remote path')).toHaveAttribute('aria-invalid', 'true'));
  expect(within(sheet).getByLabelText('File 1 remote path')).not.toHaveAttribute('aria-invalid', 'true');
  expect(within(sheet).getAllByText(/must be an absolute path/)).toHaveLength(1);
});

it('a whole-field server error shows once below the rows', async () => {
  server.use(http.patch(url('/orgs/org-1/deploy-targets/:id'), () => problem(422, 'files: required')));
  const { user, sheet } = await open();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(within(sheet).getAllByText(/files: required/)).toHaveLength(1));
});

it('saves files as path/content/mode objects', async () => {
  const { user, sheet } = await open();
  await user.clear(within(sheet).getByLabelText('File 1 remote path'));
  await user.type(within(sheet).getByLabelText('File 1 remote path'), '/etc/new.pem');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toBeDefined());
  expect((patched as { config: { files: unknown } }).config.files).toEqual([
    { path: '/etc/new.pem', content: 'fullchain', mode: '0644' },
    { path: '/etc/ssl/a.key', content: 'key', mode: '0600' },
  ]);
});
