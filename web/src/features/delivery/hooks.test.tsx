import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeHook, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { argvErrors } from '@/forms/widgets/ArgvField';

describe('argvErrors', () => {
  it('needs an absolute executable without spaces and no empty arguments', () => {
    expect(argvErrors([''])).toEqual(['Enter the executable path.']);
    expect(argvErrors(['nginx'])).toEqual(['Use an absolute path.']);
    expect(argvErrors(['/usr/sbin/nginx -s reload'])).toEqual(['One path, no spaces or arguments.']);
    expect(argvErrors(['/usr/sbin/nginx', '', '-s'])).toEqual([null, 'Enter a value or remove this argument.', null]);
    expect(argvErrors(['/usr/sbin/nginx', 'a b'])).toEqual([null, null]);
  });
});

let posted: unknown;
beforeEach(() => {
  posted = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/hooks'), () => HttpResponse.json({ items: [makeHook({ grantCount: 1 })] })),
    http.post(url('/orgs/org-1/hooks'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeHook({ id: 'h-2' }), { status: 201 });
    }),
  );
});

it('lists hooks with phase, command and timeout', async () => {
  renderRoute('/o/acme/delivery/hooks');
  const table = await screen.findByRole('table', { name: 'Hooks' });
  const row = within(table).getByText('reload nginx').closest('tr')!;
  for (const text of ['Post-deploy', '/usr/sbin/nginx -s reload', '60 s', '1 grant']) expect(within(row).getByText(text)).toBeInTheDocument();
  expect(within(table).getByRole('button', { name: 'Warning' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Delete reload nginx' })).toBeDisabled();
});

it('creates a pre-deploy hook from argv rows', async () => {
  const { user } = renderRoute('/o/acme/delivery/hooks');
  await user.click(await screen.findByRole('button', { name: 'New hook' }));
  const sheet = await screen.findByRole('dialog', { name: 'New hook' });
  await user.type(within(sheet).getByLabelText('Name'), 'test config');
  await user.click(within(sheet).getByRole('radio', { name: 'Pre-deploy' }));
  expect(within(sheet).getByRole('button', { name: 'Warning' })).toBeInTheDocument();
  await user.type(within(sheet).getByLabelText('Executable'), '/usr/sbin/nginx');
  await user.click(within(sheet).getByRole('button', { name: 'Add argument' }));
  await user.type(within(sheet).getByLabelText('Argument 1'), '-t');
  await user.click(within(sheet).getByRole('button', { name: 'Add argument' }));
  await user.type(within(sheet).getByLabelText('Argument 2'), '-q');
  await user.click(within(sheet).getByRole('button', { name: 'Move argument 2 up' }));
  await user.clear(within(sheet).getByLabelText('Timeout'));
  await user.type(within(sheet).getByLabelText('Timeout'), '30');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toEqual({ name: 'test config', phase: 'pre_deploy', argv: ['/usr/sbin/nginx', '-q', '-t'], timeoutSeconds: 30 }));
});

it('refuses a relative executable and a bad timeout', async () => {
  const { user } = renderRoute('/o/acme/delivery/hooks?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New hook' });
  await user.type(within(sheet).getByLabelText('Name'), 'bad');
  await user.type(within(sheet).getByLabelText('Executable'), 'nginx');
  await user.clear(within(sheet).getByLabelText('Timeout'));
  await user.type(within(sheet).getByLabelText('Timeout'), '0');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(within(sheet).getByText('Use an absolute path.')).toBeInTheDocument();
  expect(within(sheet).getByText('Use 1 to 3600 seconds.')).toBeInTheDocument();
  expect(posted).toBeUndefined();
});
