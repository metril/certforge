import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { OutputFile } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, makeLayout, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { accountError, emptyFile, keyReadableByOthers, modeError, validateFiles } from './layoutFiles';

const file = (p: Partial<OutputFile>): OutputFile => ({ ...emptyFile(), path: '/etc/ssl/a.pem', ...p });

describe('validateFiles', () => {
  it.each([
    ['', 'Enter a path.'],
    ['etc/ssl/a.pem', 'Use an absolute path.'],
    ['/etc/ssl/', 'Name a file, not a directory.'],
    ['/etc/../ssl/a.pem', 'Remove empty, . and .. segments.'],
    ['/etc//a.pem', 'Remove empty, . and .. segments.'],
    ['/etc/./a.pem', 'Remove empty, . and .. segments.'],
    ['/etc/\0/a.pem', 'Remove the embedded NUL character.'],
  ])('path %j', (path, msg) => expect(validateFiles([file({ path })])[0]!.path).toBe(msg));

  it('flags duplicates, empty parts, bad modes and owners', () => {
    const errs = validateFiles([file({}), file({ parts: [], mode: '999', owner: 'root user' })]);
    expect(errs[0]).toEqual({});
    expect(errs[1]).toEqual({
      path: 'Another file already uses this path.',
      parts: 'Pick at least one part.',
      mode: 'Use octal, such as 0640.',
      owner: 'Use a user/group name, or a numeric id.',
    });
  });

  it('warns only for key material readable by others', () => {
    expect(keyReadableByOthers(file({ parts: ['key'], mode: '0644' }))).toBe(true);
    expect(keyReadableByOthers(file({ parts: ['combined'], mode: '604' }))).toBe(true);
    expect(keyReadableByOthers(file({ parts: ['key'], mode: '0640' }))).toBe(false);
    expect(keyReadableByOthers(file({ parts: ['fullchain'], mode: '0644' }))).toBe(false);
  });

  it.each([
    ['0666', 'Must not be world-writable.'],
    ['0777', 'Must not be world-writable.'],
    ['999', 'Use octal, such as 0640.'],
  ])('mode %j rejects like the server', (mode, msg) => expect(modeError(mode)).toBe(msg));

  it.each([
    ['0640', null],
    ['0600', null],
  ])('mode %j is fine', (mode, msg) => expect(modeError(mode)).toBe(msg));

  it.each([
    ['Root', 'Use a user/group name, or a numeric id.'],
    ['.x', 'Use a user/group name, or a numeric id.'],
    ['-x', 'Use a user/group name, or a numeric id.'],
    ['1a', 'Use a user/group name, or a numeric id.'],
    ['99999999999', 'Use a user/group name, or a numeric id.'],
    ['4294967296', 'Numeric id must fit in 32 bits.'],
    ['4294967295', null],
    ['www-data', null],
    ['', null],
  ])('owner/group %j mirrors the server', (s, msg) => expect(accountError(s)).toBe(msg));
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
    http.get(url('/orgs/org-1/layouts'), () => HttpResponse.json({ items: [makeLayout(), makeLayout({ id: 'l-2', name: 'spare', grantCount: 0 })] })),
    http.post(url('/orgs/org-1/layouts'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeLayout({ id: 'l-3' }), { status: 201 });
    }),
    http.patch(url('/orgs/org-1/layouts/:id'), async ({ request }) => {
      patched = await request.json();
      return HttpResponse.json(makeLayout({ name: 'renamed' }));
    }),
    http.delete(url('/orgs/org-1/layouts/:id'), ({ params }) => {
      deleted.push(params.id as string);
      return new HttpResponse(null, { status: 204 });
    }),
  );
});

it('lists layouts with files and use', async () => {
  renderRoute('/o/acme/delivery/layouts');
  const table = await screen.findByRole('table', { name: 'File layouts' });
  const row = within(table).getByText('nginx').closest('tr')!;
  expect(within(row).getByText('/etc/ssl/www.pem')).toBeInTheDocument();
  expect(within(row).getByText('1 grant')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Delete nginx' })).toBeDisabled();
  expect(screen.getByRole('link', { name: 'File layouts' })).toHaveAttribute('aria-current', 'page');
});

it('builds a two-file layout with ordered parts and moves a file up', async () => {
  const { user } = renderRoute('/o/acme/delivery/layouts');
  await user.click(await screen.findByRole('button', { name: 'New layout' }));
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'haproxy');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/haproxy/certs/www.pem');
  await user.click(within(first).getByRole('button', { name: 'key' }));
  await user.clear(within(first).getByLabelText('Mode'));
  await user.type(within(first).getByLabelText('Mode'), '0600');
  await user.click(within(sheet).getByRole('button', { name: 'Add file' }));
  const second = within(sheet).getByRole('listitem', { name: 'File 2' });
  await user.type(within(second).getByLabelText('Path'), '/etc/ssl/www-chain.pem');
  await user.click(within(second).getByRole('button', { name: 'fullchain' }));
  await user.click(within(second).getByRole('button', { name: 'chain' }));
  await user.click(within(sheet).getByRole('button', { name: 'Move file 2 up' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(posted).toEqual({
      name: 'haproxy',
      files: [
        { path: '/etc/ssl/www-chain.pem', format: 'pem', parts: ['chain'], owner: '', group: '', mode: '0640' },
        { path: '/etc/haproxy/certs/www.pem', format: 'pem', parts: ['fullchain', 'key'], owner: '', group: '', mode: '0600' },
      ],
    }),
  );
});

it('shows row errors and sends nothing; warns about a world-readable key', async () => {
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'bad');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), 'relative.pem');
  await user.click(within(first).getByRole('button', { name: 'key' }));
  await user.clear(within(first).getByLabelText('Mode'));
  await user.type(within(first).getByLabelText('Mode'), '0644');
  expect(within(first).getByText('Key readable by every user')).toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(within(first).getByText('Use an absolute path.')).toBeInTheDocument();
  expect(posted).toBeUndefined();
});

it('edits a layout with a PATCH carrying name and files', async () => {
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=l-2');
  const sheet = await screen.findByRole('dialog', { name: 'Edit spare' });
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(patched).toEqual({
      name: 'spare',
      files: [{ path: '/etc/ssl/www.pem', format: 'pem', parts: ['fullchain'], owner: 'root', group: 'www-data', mode: '0640' }],
    }),
  );
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
});

it('blocks deleting a layout in use and deletes an unused one by name', async () => {
  const { user } = renderRoute('/o/acme/delivery/layouts');
  await screen.findByRole('table', { name: 'File layouts' });
  expect(screen.getByRole('button', { name: 'Delete nginx' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Delete spare' }));
  await user.type(screen.getByLabelText(/to confirm/), 'spare');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(deleted).toEqual(['l-2']));
});

it('puts a name-conflict 409 under Name and a path-collision 409 in the page alert', async () => {
  server.use(http.post(url('/orgs/org-1/layouts'), () => problem(409, 'A layout named "nginx" exists in this org.')));
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'nginx');
  await user.type(within(within(sheet).getByRole('listitem', { name: 'File 1' })).getByLabelText('Path'), '/etc/ssl/a.pem');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByText('A layout named "nginx" exists in this org.')).toBeInTheDocument();

  server.use(http.post(url('/orgs/org-1/layouts'), () => problem(409, 'The grants for "web-1/www" and "web-2/api" on this client would both write /etc/ssl/a.pem; use a different layout path or deploy target.')));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  const alert = await within(sheet).findByText(/would both write/);
  expect(alert.closest('[role="alert"]')).toBeInTheDocument();
});

it('maps a 422 field error back to its row', async () => {
  server.use(http.post(url('/orgs/org-1/layouts'), () => problem(422, 'mode must not be world-writable', {}, 'Invalid files[0].mode')));
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'bad');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/a.pem');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(first).findByText('mode must not be world-writable')).toBeInTheDocument();
});

it('is read-only for a viewer', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/delivery/layouts');
  expect(await screen.findByRole('button', { name: 'New layout' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'View nginx' }));
  const sheet = await screen.findByRole('dialog', { name: 'nginx' });
  expect(within(sheet).getByLabelText('Name')).toBeDisabled();
  expect(within(sheet).queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
});

it('never opens the add sheet for a viewer, even with ?edit=new', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/delivery/layouts?edit=new');
  await screen.findByRole('table', { name: 'File layouts' });
  expect(screen.queryByRole('dialog', { name: 'New layout' })).not.toBeInTheDocument();
});
