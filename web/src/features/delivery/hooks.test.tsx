import { http, HttpResponse } from 'msw';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeHook, meWith, org, problem, url } from '@/test/fixtures';
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

let posted: unknown;
let patched: unknown;
let deleted: string[];

beforeEach(() => {
  posted = undefined;
  patched = undefined;
  deleted = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/hooks'), () =>
      HttpResponse.json({
        items: [makeHook({ grantCount: 1 }), makeHook({ id: 'h-2', name: 'reload apache', argv: ['/usr/sbin/apachectl', 'graceful'], grantCount: 0 })],
      }),
    ),
    http.post(url('/orgs/org-1/hooks'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeHook({ id: 'h-3' }), { status: 201 });
    }),
    http.patch(url('/orgs/org-1/hooks/:id'), async ({ request }) => {
      patched = await request.json();
      return HttpResponse.json(makeHook());
    }),
    http.delete(url('/orgs/org-1/hooks/:id'), ({ params }) => {
      deleted.push(params.id as string);
      return new HttpResponse(null, { status: 204 });
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

it('removes an argument row and moves focus to the nearest remaining row', async () => {
  const { user } = renderRoute('/o/acme/delivery/hooks?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New hook' });
  await user.click(within(sheet).getByRole('button', { name: 'Add argument' }));
  await user.type(within(sheet).getByLabelText('Argument 1'), '-s');
  await user.click(within(sheet).getByRole('button', { name: 'Add argument' }));
  await user.type(within(sheet).getByLabelText('Argument 2'), 'reload');
  await user.click(within(sheet).getByRole('button', { name: 'Remove argument 1' }));
  expect(within(sheet).queryByLabelText('Argument 2')).not.toBeInTheDocument();
  const remaining = within(sheet).getByLabelText('Argument 1');
  expect(remaining).toHaveValue('reload');
  await waitFor(() => expect(remaining).toHaveFocus());
});

it('caps the command at 64 entries', async () => {
  renderRoute('/o/acme/delivery/hooks?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New hook' });
  const add = within(sheet).getByRole('button', { name: 'Add argument' });
  // fireEvent (not userEvent): userEvent's full pointer simulation is
  // wasted on a plain click loop with no hover/focus behaviour under test.
  // 63 re-renders of the sheet still take several seconds under vitest.
  for (let i = 0; i < 63; i++) fireEvent.click(add);
  expect(within(sheet).getByLabelText('Argument 63')).toBeInTheDocument();
  expect(add).toBeDisabled();
}, 20000);

it('edits a hook with a PATCH carrying the full body', async () => {
  const { user } = renderRoute('/o/acme/delivery/hooks?edit=h-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit reload nginx' });
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toEqual({ name: 'reload nginx', phase: 'post_deploy', argv: ['/usr/sbin/nginx', '-s', 'reload'], timeoutSeconds: 60 }));
});

it('deletes an unused hook via the confirm dialog', async () => {
  const { user } = renderRoute('/o/acme/delivery/hooks');
  await screen.findByRole('table', { name: 'Hooks' });
  await user.click(screen.getByRole('button', { name: 'Delete reload apache' }));
  await user.type(screen.getByLabelText(/to confirm/), 'reload apache');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(deleted).toEqual(['h-2']));
});

it('shows a raced 409 (still used) inside the delete dialog', async () => {
  server.use(http.delete(url('/orgs/org-1/hooks/:id'), () => problem(409, 'Used by web-1/www.')));
  const { user } = renderRoute('/o/acme/delivery/hooks');
  await user.click(await screen.findByRole('button', { name: 'Delete reload apache' }));
  await user.type(screen.getByLabelText(/to confirm/), 'reload apache');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  expect(await within(screen.getByRole('dialog')).findByText('Used by web-1/www.')).toBeInTheDocument();
});

it('puts a name-conflict 409 under Name and any other error in the page alert', async () => {
  server.use(http.post(url('/orgs/org-1/hooks'), () => problem(409, 'A hook named "reload nginx" already exists in this org.')));
  const { user } = renderRoute('/o/acme/delivery/hooks?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New hook' });
  await user.type(within(sheet).getByLabelText('Name'), 'reload nginx');
  await user.type(within(sheet).getByLabelText('Executable'), '/usr/sbin/nginx');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByText('A hook named "reload nginx" already exists in this org.')).toBeInTheDocument();
  expect(within(sheet).getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true');

  server.use(http.post(url('/orgs/org-1/hooks'), () => problem(422, 'timeoutSeconds must be 1 to 3600 seconds')));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  const alert = await within(sheet).findByText('timeoutSeconds must be 1 to 3600 seconds');
  expect(alert.closest('[role="alert"]')).toBeInTheDocument();
  expect(within(sheet).getByLabelText('Name')).not.toHaveAttribute('aria-invalid', 'true');

  server.use(http.post(url('/orgs/org-1/hooks'), () => problem(500, 'boom')));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByText('boom')).toBeInTheDocument();
});

it('is read-only for a viewer, even with ?edit=new', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/delivery/hooks?edit=new');
  await screen.findByRole('table', { name: 'Hooks' });
  expect(screen.queryByRole('dialog', { name: 'New hook' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'New hook' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'View reload nginx' }));
  const sheet = await screen.findByRole('dialog', { name: 'reload nginx' });
  expect(within(sheet).getByLabelText('Name')).toBeDisabled();
  expect(within(sheet).queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
});

it('clears an unknown ?edit= id and reports it', async () => {
  renderRoute('/o/acme/delivery/hooks?edit=nope');
  await screen.findByRole('table', { name: 'Hooks' });
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(await screen.findByText('Hook not found.')).toBeInTheDocument();
});
