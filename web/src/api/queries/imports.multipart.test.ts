// @vitest-environment node
//
// Adaptation (discovered while implementing this test): jsdom's Blob has no
// working `stream()` (jsdom implements Blob/File/FormData for its own DOM
// surfaces, but not the Streams-backed body jsdom's own fetch does NOT
// provide). Node's native fetch/Request, asked to read a multipart body
// built from a jsdom File, gets exactly one chunk from the bridged stream
// and then hangs forever waiting for a `done` signal that never arrives —
// so an msw handler's `await request.formData()` never resolves. This is a
// jsdom/environment gap, not an application bug (a real browser's File has
// a working stream()); test/setup.ts already anticipates exactly this class
// of test ("some test files opt into `@vitest-environment node` ... where
// these DOM globals don't exist"). Isolating the multipart-body assertion
// in its own node-environment file sidesteps the gap entirely, since a
// plain Node environment's File/FormData/Request are fully native and never
// touch jsdom. The "create invalidates certs" test stays in imports.test.ts
// (jsdom), since it needs renderHook/DOM and never drives a real multipart
// body through msw.
import { http, HttpResponse } from 'msw';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { makeImportResult, me, url } from '@/test/fixtures';

// The jsdom environment (see vitest.config.ts) sets window.location so
// client.ts's baseUrl (`${globalThis.location?.origin ?? ''}${API_BASE}`)
// resolves to an absolute URL; the plain node environment has no
// `location` at all. `./imports` is imported dynamically, after this runs,
// so `../client`'s module-top `createClient({ baseUrl: ... })` sees it.
globalThis.location = { origin: 'http://localhost:3000' } as Location;

it('multipart body: archive is a File, caId and dryRun ride along as form fields', async () => {
  const { importCertificates } = await import('./imports');
  let fileName = '';
  let caId = '';
  let dryRun = '';
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(me)),
    http.post(url('/orgs/org-1/certificates/import'), async ({ request }) => {
      const fd = await request.formData();
      const archive = fd.get('archive');
      fileName = archive instanceof File ? archive.name : '';
      caId = String(fd.get('caId'));
      dryRun = String(fd.get('dryRun'));
      return HttpResponse.json(makeImportResult());
    }),
  );
  const archive = new File(['tar-bytes'], 'acme-state.tar', { type: 'application/x-tar' });
  await importCertificates('org-1', { archive, caId: 'ca-1', dryRun: true });
  expect(fileName).toBe('acme-state.tar');
  expect(caId).toBe('ca-1');
  expect(dryRun).toBe('true');
});
