import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { OutputFile } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, makeLayout, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { emptyFile, keyReadableByOthers, validateFiles } from './layoutFiles';

const file = (p: Partial<OutputFile>): OutputFile => ({ ...emptyFile(), path: '/etc/ssl/a.pem', ...p });

describe('validateFiles', () => {
  it.each([
    ['', 'Enter a path.'],
    ['etc/ssl/a.pem', 'Use an absolute path.'],
    ['/etc/ssl/', 'Name a file, not a directory.'],
    ['/etc/../ssl/a.pem', 'Remove empty, . and .. segments.'],
    ['/etc//a.pem', 'Remove empty, . and .. segments.'],
    ['/etc/./a.pem', 'Remove empty, . and .. segments.'],
  ])('path %j', (path, msg) => expect(validateFiles([file({ path })])[0]!.path).toBe(msg));

  it('flags duplicates, empty parts, bad modes and owners', () => {
    const errs = validateFiles([file({}), file({ parts: [], mode: '999', owner: 'root user' })]);
    expect(errs[0]).toEqual({});
    expect(errs[1]).toEqual({ path: 'Another file already uses this path.', parts: 'Pick at least one part.', mode: 'Use octal, such as 0640.', owner: 'Letters, digits, dot, dash or underscore.' });
  });

  it('warns only for key material readable by others', () => {
    expect(keyReadableByOthers(file({ parts: ['key'], mode: '0644' }))).toBe(true);
    expect(keyReadableByOthers(file({ parts: ['combined'], mode: '604' }))).toBe(true);
    expect(keyReadableByOthers(file({ parts: ['key'], mode: '0640' }))).toBe(false);
    expect(keyReadableByOthers(file({ parts: ['fullchain'], mode: '0644' }))).toBe(false);
  });
});

let posted: unknown;
beforeEach(() => {
  posted = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/layouts'), () => HttpResponse.json({ items: [makeLayout(), makeLayout({ id: 'l-2', name: 'spare', grantCount: 0 })] })),
    http.post(url('/orgs/org-1/layouts'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeLayout({ id: 'l-3' }), { status: 201 });
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
