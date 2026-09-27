import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, ca, makeImportItem, makeImportResult, meWith, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// D1: desktop by default so preview tests render the table; the 375px card
// test overrides this, mirroring audit.test.tsx's own stub convention.
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

beforeEach(() => {
  stubViewport(true);
  server.use(...authHandlers({ authed: true }), http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])));
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// Reading the archive back out of the request body (`request.formData()`)
// hangs forever under jsdom: a real browser's File has a working
// `stream()`, but jsdom's does not, and Node's fetch/Request — asked to
// re-parse a multipart body built from a jsdom File — gets one chunk from
// the bridged stream and then waits for a `done` it never receives (see
// api/queries/imports.multipart.test.ts, which sidesteps this with a plain
// node environment instead). `FormData.prototype.append` is called
// synchronously while the *client* builds the request, before any of that
// streaming happens, so spying on it captures the same `caId`/`dryRun`
// fields without ever touching the broken stream; the msw handlers below
// never call `request.formData()`.
function captureFormData(): Record<string, string> {
  const seen: Record<string, string> = {};
  const origAppend = FormData.prototype.append;
  vi.spyOn(FormData.prototype, 'append').mockImplementation(function (this: FormData, name: string, value: unknown) {
    if (typeof value === 'string') seen[name] = value;
    return origAppend.call(this, name, value as never);
  });
  return seen;
}

async function pickArchiveAndCa(user: ReturnType<typeof renderRoute>['user'], fileName = 'site.zip') {
  const archive = new File(['zip-bytes'], fileName, { type: 'application/zip' });
  await user.upload(await screen.findByLabelText('Archive'), archive);
  await user.click(screen.getByRole('combobox', { name: 'CA' }));
  // The option's accessible name also picks up its trailing preset hint
  // ("letsencrypt"), so this matches on the CA name as a substring.
  await user.click(await screen.findByRole('option', { name: /Let's Encrypt/ }));
}

it('preview: uploads an archive, picks a CA, and previews with dryRun true', async () => {
  const seen = captureFormData();
  server.use(
    http.post(url('/orgs/org-1/certificates/import'), () =>
      HttpResponse.json(
        makeImportResult({
          items: [
            makeImportItem({ name: 'www', action: 'create', reason: 'new certificate' }),
            makeImportItem({ name: 'api', action: 'skip', reason: 'a certificate named api already exists' }),
          ],
        }),
      ),
    ),
  );
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText('1 to create · 1 skipped')).toBeInTheDocument();
  const table = await screen.findByRole('table', { name: 'Import preview' });
  expect(within(table).getByText('Create')).toBeInTheDocument();
  expect(within(table).getByText('Skip')).toBeInTheDocument();
  expect(within(table).getByText('a certificate named api already exists')).toBeInTheDocument();
  await waitFor(() => expect(seen.dryRun).toBe('true'));
  expect(seen.caId).toBe('ca-1');
});

it('import sends dryRun false and links created rows', async () => {
  // The dry run and the real run go through the same handler; it echoes
  // back whichever `dryRun` this call's own FormData carried (captured
  // synchronously below, before that call's request is even sent), so the
  // second (real) call's response differs from the first (preview) one —
  // matching the real server's "identical except for dryRun" contract.
  const seen = captureFormData();
  server.use(
    http.post(url('/orgs/org-1/certificates/import'), () => {
      const real = seen.dryRun === 'false';
      return HttpResponse.json(
        makeImportResult({
          dryRun: !real,
          items: [
            makeImportItem({ name: 'www', action: 'create', certificateId: real ? 'c-new' : undefined }),
            makeImportItem({ name: 'api', action: 'create', certificateId: real ? 'c-new-2' : undefined }),
          ],
        }),
      );
    }),
  );
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  await user.click(await screen.findByRole('button', { name: 'Import 2 certificates' }));
  expect(await screen.findByText('Imported 2 certificates')).toBeInTheDocument();
  await waitFor(() => expect(seen.dryRun).toBe('false'));
  const link = screen.getByRole('link', { name: 'www' });
  expect(link).toHaveAttribute('href', '/o/acme/certificates/c-new/overview');
});

it('changing the file or CA clears the preview', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/import'), () => HttpResponse.json(makeImportResult())));
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  await screen.findByRole('table', { name: 'Import preview' });
  await user.click(screen.getByRole('button', { name: 'Replace' }));
  await user.upload(screen.getByLabelText('Archive'), new File(['other'], 'other.zip', { type: 'application/zip' }));
  expect(screen.queryByRole('table', { name: 'Import preview' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Import \d+ certificates?/ })).not.toBeInTheDocument();
});

it('archive too large: shows an inline error and sends no request', async () => {
  let posted = false;
  server.use(http.post(url('/orgs/org-1/certificates/import'), () => ((posted = true), HttpResponse.json(makeImportResult()))));
  const { user } = renderRoute('/o/acme/certificates/import');
  const big = new File([new Uint8Array(33 * 1024 * 1024)], 'huge.zip', { type: 'application/zip' });
  await user.upload(await screen.findByLabelText('Archive'), big);
  expect(await screen.findByText('Larger than 32 MiB.')).toBeInTheDocument();
  await user.click(screen.getByRole('combobox', { name: 'CA' }));
  await user.click(await screen.findByRole('option', { name: /Let's Encrypt/ }));
  expect(screen.getByRole('button', { name: 'Preview' })).toBeDisabled();
  expect(posted).toBe(false);
});

it('no account 422 under CA', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/import'), () => problem(422, 'No ACME account is registered for this CA in this org.')));
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText('No ACME account is registered for this CA in this org.')).toBeInTheDocument();
});

it('empty archive', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/import'), () => HttpResponse.json(makeImportResult({ items: [] }))));
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText('No acme.sh or certbot certificates in this archive.')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Choose another file' }));
  expect(screen.queryByText('No acme.sh or certbot certificates in this archive.')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Archive')).toBeInTheDocument();
});

it('viewer: controls are disabled behind a permission tooltip', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))));
  renderRoute('/o/acme/certificates/import');
  expect(await screen.findByLabelText('Archive')).toBeDisabled();
  expect(screen.getByRole('combobox', { name: 'CA' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Preview' })).toBeDisabled();
});

it('375px: card rows instead of a table', async () => {
  stubViewport(false);
  server.use(
    http.post(url('/orgs/org-1/certificates/import'), () =>
      HttpResponse.json(makeImportResult({ items: [makeImportItem({ name: 'www' }), makeImportItem({ name: 'api', action: 'skip', reason: 'name in use' })] })),
    ),
  );
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  await screen.findByText('1 to create · 1 skipped');
  expect(screen.queryByRole('table', { name: 'Import preview' })).not.toBeInTheDocument();
  expect(screen.getByText('www')).toBeInTheDocument();
  expect(screen.getByText('api')).toBeInTheDocument();
});
