import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { OutputFile } from '@/api/types';
import { help } from '@/lib/help';
import { server } from '@/test/server';
import { authHandlers, makeCert, makeLayout, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { accountError, emptyFile, keyReadableByOthers, layoutErrors, modeError, validateFiles } from './layoutFiles';

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

describe('layoutErrors', () => {
  const p12Files = [{ ...emptyFile(), format: 'p12' as const, parts: [] }];
  const jksFiles = [{ ...emptyFile(), format: 'jks' as const, parts: [] }];

  // Review fix round 1: internal/api/delivery.go's checkLayoutPassword uses
  // Go's len(string), which counts UTF-8 bytes, not runes — a password of
  // multi-byte characters can be within the code-point count the old
  // [...pw].length check used while still over the server's byte limit.
  it('counts the password by UTF-8 bytes, not code points', () => {
    const at128Bytes = 'é'.repeat(64); // 64 code points, 128 bytes (2 bytes each) — exactly at the limit.
    expect(layoutErrors({ files: p12Files, password: at128Bytes, passwordSet: false, extraCertificateIds: [] })).toEqual({});
    const over128Bytes = 'é'.repeat(65); // 65 code points, 130 bytes — over the server's byte limit.
    expect(layoutErrors({ files: p12Files, password: over128Bytes, passwordSet: false, extraCertificateIds: [] }).password).toBe('At most 128 characters.');
  });

  // render.CheckJKSPassword requires ASCII *and* at least 6 characters, only
  // when a file is jks; a non-ASCII password of 6+ code points must still
  // fail, and an ASCII one under 6 must still fail. Fix wave (Minor): the
  // two checks now report their own message, matching DownloadSheet's own
  // passwordError — a non-ASCII password used to say "At least 6
  // characters.", which is true but not why it was rejected.
  it('requires ASCII and at least 6 characters only when a file is jks', () => {
    expect(layoutErrors({ files: jksFiles, password: 'héllo1', passwordSet: false, extraCertificateIds: [] }).password).toBe('ASCII characters only.');
    expect(layoutErrors({ files: jksFiles, password: 'ab', passwordSet: false, extraCertificateIds: [] }).password).toBe('At least 6 characters.');
    expect(layoutErrors({ files: jksFiles, password: 'hello1', passwordSet: false, extraCertificateIds: [] })).toEqual({});
    // A non-ASCII password is fine for a plain p12 file (no jks rule applies).
    expect(layoutErrors({ files: p12Files, password: 'héllo1', passwordSet: false, extraCertificateIds: [] })).toEqual({});
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
    http.get(url('/orgs/org-1/layouts'), () => HttpResponse.json({ items: [makeLayout(), makeLayout({ id: 'l-2', name: 'spare', grantCount: 0 })] })),
    // Every LayoutSheet render fetches all-certificates for the extra
    // certificates combobox; tests that care about its contents override this.
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [], nextCursor: null })),
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
  server.use(
    http.get(url('/orgs/org-1/layouts'), () =>
      HttpResponse.json({ items: [makeLayout({ passwordSet: true, extraCertificateIds: ['c-2', 'c-3'] }), makeLayout({ id: 'l-2', name: 'spare', grantCount: 0 })] }),
    ),
  );
  renderRoute('/o/acme/delivery/layouts');
  const table = await screen.findByRole('table', { name: 'File layouts' });
  const row = within(table).getByText('nginx').closest('tr')!;
  expect(within(row).getByText(/www\.pem · \+2 extra · password set/)).toBeInTheDocument();
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
  await user.click(within(first).getByRole('button', { name: 'Advanced' }));
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
      extraCertificateIds: [],
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
  await user.click(within(first).getByRole('button', { name: 'Advanced' }));
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
      extraCertificateIds: [],
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
  expect(within(sheet).getByRole('radio', { name: 'PEM' })).toBeDisabled();
  expect(within(sheet).getByRole('combobox', { name: 'Extra certificates' })).toBeDisabled();
  expect(within(sheet).queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
});

it('format switch adapts parts: DER shows Certificate/Key, PKCS#12 sends parts: [] with its encoding', async () => {
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'store');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/bundle.p12');
  await user.click(within(first).getByRole('radio', { name: 'DER' }));
  expect(within(first).getByRole('radio', { name: 'Certificate' })).toBeInTheDocument();
  expect(within(first).getByRole('radio', { name: 'Key' })).toBeInTheDocument();
  await user.click(within(first).getByRole('radio', { name: 'PKCS#12' }));
  expect(within(first).queryByRole('radio', { name: 'Certificate' })).not.toBeInTheDocument();
  expect(within(first).getByRole('radio', { name: 'Modern' })).toBeInTheDocument();
  await user.click(within(first).getByRole('radio', { name: 'Legacy' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(posted).toMatchObject({ files: [expect.objectContaining({ format: 'p12', parts: [], encoding: 'legacy' })] }),
  );
});

it('p12 needs password: Save is blocked with the inline error', async () => {
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'store');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/bundle.p12');
  await user.click(within(first).getByRole('radio', { name: 'PKCS#12' }));
  await user.clear(within(sheet).getByLabelText('Password'));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(within(sheet).getByText('Enter a password.')).toBeInTheDocument();
  expect(posted).toBeUndefined();
});

it('layout password write-only: create sends a fresh password, cleared from the mutation cache after save', async () => {
  const { user, queryClient } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'vault');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/bundle.p12');
  await user.click(within(first).getByRole('radio', { name: 'PKCS#12' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toBeDefined());
  const sent = (posted as { password: string }).password;
  expect(sent).not.toBe('');
  expect(sent).not.toBe('__unchanged__');
  expect(sent.length).toBeGreaterThanOrEqual(6);
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
});

it('layout password write-only: edit sends __unchanged__ unless replaced, and never keeps a typed value across reopens', async () => {
  server.use(
    http.get(url('/orgs/org-1/layouts'), () =>
      HttpResponse.json({
        items: [makeLayout({ passwordSet: true, files: [{ path: '/etc/ssl/bundle.p12', format: 'p12', parts: [], owner: '', group: '', mode: '0600' }] })],
      }),
    ),
  );
  const { user, queryClient } = renderRoute('/o/acme/delivery/layouts?edit=l-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit nginx' });
  expect(within(sheet).getByText('Stored')).toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ password: '__unchanged__' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));

  patched = undefined;
  await user.click(screen.getByRole('button', { name: 'Edit nginx' }));
  const sheet2 = await screen.findByRole('dialog', { name: 'Edit nginx' });
  await user.click(within(sheet2).getByRole('button', { name: 'Replace Password' }));
  await user.type(within(sheet2).getByLabelText('Password'), 'temporary-value');
  await user.click(within(sheet2).getByRole('button', { name: 'Cancel' }));
  await user.click(await screen.findByRole('button', { name: 'Discard' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

  await user.click(screen.getByRole('button', { name: 'Edit nginx' }));
  const sheet3 = await screen.findByRole('dialog', { name: 'Edit nginx' });
  expect(within(sheet3).getByText('Stored')).toBeInTheDocument();
  expect(within(sheet3).queryByDisplayValue('temporary-value')).not.toBeInTheDocument();
  await user.click(within(sheet3).getByRole('button', { name: 'Replace Password' }));
  await user.type(within(sheet3).getByLabelText('Password'), 'new-secret-1');
  await user.click(within(sheet3).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ password: 'new-secret-1' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
});

it('removes a stored password when no file needs one', async () => {
  server.use(
    http.get(url('/orgs/org-1/layouts'), () =>
      HttpResponse.json({
        items: [makeLayout({ passwordSet: true, files: [{ path: '/etc/ssl/www.pem', format: 'pem', parts: ['fullchain'], owner: '', group: '', mode: '0640' }] })],
      }),
    ),
  );
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=l-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit nginx' });
  expect(within(sheet).getByRole('button', { name: 'Remove Password' })).toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Remove Password' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ password: '' }));
});

// Fix wave (Minor): the generated layout password had Show/Generate but no
// Copy, unlike DownloadSheet's own generated password.
it('generated layout password has a Copy button that writes it to the clipboard', async () => {
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'store');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/bundle.p12');
  await user.click(within(first).getByRole('radio', { name: 'PKCS#12' }));
  const pwField = within(sheet).getByLabelText('Password') as HTMLInputElement;
  await user.click(within(sheet).getByRole('button', { name: 'Copy password' }));
  expect(await navigator.clipboard.readText()).toBe(pwField.value);
});

it('clears a JKS alias to undefined instead of an empty string once cleared', async () => {
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'jks-store');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/keystore.jks');
  await user.click(within(first).getByRole('radio', { name: 'JKS' }));
  await user.type(within(first).getByLabelText('Alias'), 'tomcat');
  await user.clear(within(first).getByLabelText('Alias'));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toBeDefined());
  expect((posted as { files: { alias?: string }[] }).files[0]).not.toHaveProperty('alias');
});

it('clears the extra part from every PEM file once the last extra certificate is removed', async () => {
  server.use(http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [makeCert({ id: 'c-2', name: 'api' })], nextCursor: null })));
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'bundle');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/all.pem');

  await user.click(within(sheet).getByRole('combobox', { name: 'Extra certificates' }));
  await user.click(await screen.findByRole('option', { name: 'api' }));
  await user.keyboard('{Escape}');
  await user.click(within(first).getByRole('button', { name: 'extra' }));
  expect(within(first).getByRole('button', { name: 'extra' })).toBeEnabled();

  await user.click(within(sheet).getByRole('button', { name: 'Remove api' }));
  expect(within(first).getByRole('button', { name: 'extra' })).toBeDisabled();

  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toBeDefined());
  const savedParts = (posted as { files: { parts: string[] }[] }).files[0]!.parts;
  expect(savedParts).not.toContain('extra');
  expect(savedParts).toContain('fullchain');
});

// Fix wave (Important, disabled-never-hidden): Remove used to be omitted
// outright while a file still needed the password; it now shows disabled,
// with a tooltip naming why.
it('disables Remove (never hides it) for the layout password while a file is p12/jks', async () => {
  server.use(
    http.get(url('/orgs/org-1/layouts'), () =>
      HttpResponse.json({
        items: [makeLayout({ passwordSet: true, files: [{ path: '/etc/ssl/bundle.p12', format: 'p12', parts: [], owner: '', group: '', mode: '0600' }] })],
      }),
    ),
  );
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=l-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit nginx' });
  const removeButton = within(sheet).getByRole('button', { name: 'Remove Password' });
  expect(removeButton).toBeDisabled();
  await user.hover(removeButton);
  expect(await screen.findByText(help['layout.passwordNeeded'].text)).toBeInTheDocument();
  expect(within(sheet).getByRole('button', { name: 'Replace Password' })).toBeInTheDocument();
});

it('extra certificates: picking 2 sends extraCertificateIds in order and enables the extra chip', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates'), () =>
      HttpResponse.json({ items: [makeCert(), makeCert({ id: 'c-2', name: 'api' }), makeCert({ id: 'c-3', name: 'mail' })], nextCursor: null }),
    ),
  );
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'bundle');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/all.pem');
  expect(within(first).getByRole('button', { name: 'extra' })).toBeDisabled();

  await user.click(within(sheet).getByRole('combobox', { name: 'Extra certificates' }));
  await user.click(await screen.findByRole('option', { name: 'mail' }));
  await user.click(screen.getByRole('option', { name: 'api' }));
  await user.keyboard('{Escape}');

  expect(within(first).getByRole('button', { name: 'extra' })).toBeEnabled();
  await user.click(within(first).getByRole('button', { name: 'extra' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ extraCertificateIds: ['c-3', 'c-2'] }));
});

it('server 422 on password maps to the layout-level field', async () => {
  server.use(http.post(url('/orgs/org-1/layouts'), () => problem(422, 'must be ASCII and at least 6 characters when any file is jks', {}, 'Invalid password')));
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New layout' });
  await user.type(within(sheet).getByLabelText('Name'), 'jks-store');
  const first = within(sheet).getByRole('listitem', { name: 'File 1' });
  await user.type(within(first).getByLabelText('Path'), '/etc/ssl/keystore.jks');
  await user.click(within(first).getByRole('radio', { name: 'JKS' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByText('must be ASCII and at least 6 characters when any file is jks')).toBeInTheDocument();
});

it('never opens the add sheet for a viewer, even with ?edit=new', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/delivery/layouts?edit=new');
  await screen.findByRole('table', { name: 'File layouts' });
  expect(screen.queryByRole('dialog', { name: 'New layout' })).not.toBeInTheDocument();
});

it('clears an unknown ?edit= id and reports it', async () => {
  renderRoute('/o/acme/delivery/layouts?edit=nope');
  await screen.findByRole('table', { name: 'File layouts' });
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(await screen.findByText('File layout not found.')).toBeInTheDocument();
});

it('disables Save with a keys:export tooltip when an in-use layout gains a key file', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=l-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit nginx' });
  expect(within(sheet).getByRole('button', { name: 'Save' })).toBeEnabled();
  await user.click(within(sheet).getByRole('button', { name: 'key' }));
  const save = within(sheet).getByRole('button', { name: 'Save' });
  expect(save).toBeDisabled();
  await user.hover(save.parentElement!);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the keys:export permission');
});

it('keeps Save enabled for an unused layout gaining a key file', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/delivery/layouts?edit=l-2');
  const sheet = await screen.findByRole('dialog', { name: 'Edit spare' });
  await user.click(within(sheet).getByRole('button', { name: 'key' }));
  expect(within(sheet).getByRole('button', { name: 'Save' })).toBeEnabled();
});
