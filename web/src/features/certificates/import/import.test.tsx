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
  // Fix round 1: re-clicking Import after a real run already landed would
  // diverge from the identical dry-run/real-run contract (names now exist,
  // so a second run would show them as skips) — the button stays disabled
  // once `result` is itself a real (non-dry) one.
  expect(screen.getByRole('button', { name: 'Import 2 certificates' })).toBeDisabled();
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
  const { user } = renderRoute('/o/acme/certificates/import');
  expect(await screen.findByLabelText('Archive')).toBeDisabled();
  expect(screen.getByRole('combobox', { name: 'CA' })).toBeDisabled();
  const preview = screen.getByRole('button', { name: 'Preview' });
  expect(preview).toBeDisabled();
  // Fix round 1: a disabled control alone doesn't prove PermissionTip wraps
  // it (it would also be disabled by `!ready`) — hover the wrapping span
  // and see the "Needs the certs:write permission" tooltip PermissionTip
  // renders, the same way list.test.tsx proves Import's own gating.
  await user.hover(preview.closest('span')!);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the certs:write permission');
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
  // One card per item: each ImportCard's own `dl` has exactly one "Names"
  // term, so its count is the card count, not just "some card rendered".
  expect(screen.getAllByText('Names')).toHaveLength(2);
});

// Fix round 1 (review, Important): the archive File (private keys, for a
// managed import that includes a key) must not linger in the MutationCache
// after the page is done with it — `gcTime: 0` on useImportCertificates,
// matching useSaveCa's own EAB-HMAC fix.
it('drops the mutation (and its archive File) from the cache once nothing observes it', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/import'), () => HttpResponse.json(makeImportResult())));
  const { user, queryClient, unmount } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  await screen.findByRole('table', { name: 'Import preview' });
  unmount();
  await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
});

// Fix round 1 (review, Important): the sr-only file input had no visible
// focus indicator of its own; the wrapper must show one so a keyboard user
// tabbing to it can see where focus is, in both the empty and file-chosen
// states (input.tsx's own focus-visible ring tokens).
it('both dropzone states carry a focus ring for the hidden input', async () => {
  renderRoute('/o/acme/certificates/import');
  const input = await screen.findByLabelText('Archive');
  expect(input.parentElement).toHaveClass('focus-within:border-ring', 'focus-within:ring-[3px]', 'focus-within:ring-ring/50');
});

it('a chosen archive keeps the focus ring on its own wrapper', async () => {
  const { user } = renderRoute('/o/acme/certificates/import');
  await user.upload(await screen.findByLabelText('Archive'), new File(['zip-bytes'], 'site.zip', { type: 'application/zip' }));
  const input = screen.getByLabelText('Archive');
  expect(input.parentElement).toHaveClass('focus-within:border-ring', 'focus-within:ring-[3px]', 'focus-within:ring-ring/50');
});

it('a 413 from the server (not just the client precheck) shows under Archive', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/import'), () => problem(413, 'Payload too large.')));
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText('Larger than 32 MiB.')).toBeInTheDocument();
});

it('a 415 shows under Archive', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/import'), () => problem(415, 'Not a zip or tar.gz archive.')));
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText('Not a zip or tar.gz archive.')).toBeInTheDocument();
});

it('a generic error shows ErrorState with Retry', async () => {
  let calls = 0;
  server.use(
    http.post(url('/orgs/org-1/certificates/import'), () => {
      calls++;
      return calls === 1 ? problem(500, 'Something went wrong.') : HttpResponse.json(makeImportResult());
    }),
  );
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText('Something went wrong.')).toBeInTheDocument();
  const retry = screen.getByRole('button', { name: 'Retry' });
  await user.click(retry);
  await screen.findByRole('table', { name: 'Import preview' });
  expect(calls).toBe(2);
});

it('a failure after some certificates were created says how many and lists them', async () => {
  server.use(
    http.post(url('/orgs/org-1/certificates/import'), () =>
      HttpResponse.json(
        {
          type: 'about:blank',
          title: 'Internal server error',
          status: 500,
          imported: [makeImportItem({ name: 'www', action: 'create', certificateId: 'c-new' })],
        },
        { status: 500, headers: { 'Content-Type': 'application/problem+json' } },
      ),
    ),
  );
  const { user } = renderRoute('/o/acme/certificates/import');
  await pickArchiveAndCa(user);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText(/Import failed after creating 1 certificate\./)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'www' })).toHaveAttribute('href', '/o/acme/certificates/c-new/overview');
  expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
});
