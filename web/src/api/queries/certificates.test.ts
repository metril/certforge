import { http, HttpResponse } from 'msw';
import { beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { problem, url } from '@/test/fixtures';
import { downloadVersion, exportVersion } from './certificates';

beforeEach(() => {
  URL.createObjectURL = vi.fn(() => 'blob:test');
  URL.revokeObjectURL = vi.fn();
  // saveBlob() clicks a real anchor; jsdom logs an unimplemented-navigation
  // warning unless the click is stubbed (also done inline where a test
  // asserts on the click itself, below).
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
});

it('DER download sends format=der&parts=cert', async () => {
  let query: URLSearchParams | undefined;
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/versions/v-1/download'), ({ request }) => {
      query = new URL(request.url).searchParams;
      return new HttpResponse('DER bytes', {
        headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="www.der"' },
      });
    }),
  );
  await downloadVersion('org-1', 'c-1', 'v-1', { format: 'der', parts: ['cert'] }, 'www');
  expect(query?.get('format')).toBe('der');
  expect(query?.get('parts')).toBe('cert');
});

it('export posts JSON, keeps the password out of the URL, and saves the name from Content-Disposition', async () => {
  const click = vi.mocked(HTMLAnchorElement.prototype.click);
  let method = '';
  let requestUrl = '';
  let body: unknown;
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/export'), async ({ request }) => {
      method = request.method;
      requestUrl = request.url;
      body = await request.json();
      return new HttpResponse('PK', {
        headers: { 'Content-Type': 'application/x-pkcs12', 'Content-Disposition': 'attachment; filename="www.p12"' },
      });
    }),
  );
  await exportVersion('org-1', 'c-1', 'v-1', { format: 'p12', password: 'correct horse battery', encoding: 'modern' }, 'www');
  expect(method).toBe('POST');
  expect(body).toEqual({ format: 'p12', password: 'correct horse battery', encoding: 'modern' });
  expect(new URL(requestUrl).search).toBe('');
  expect(new URL(requestUrl).pathname).not.toContain('password');
  expect(click).toHaveBeenCalled();
  expect((click.mock.contexts[0] as HTMLAnchorElement).download).toBe('www.p12');
});

it('export 422 throws an ApiError carrying problem.title', async () => {
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/export'), () =>
      problem(422, 'password must be at least 6 characters for jks', {}, 'Invalid password'),
    ),
  );
  await expect(exportVersion('org-1', 'c-1', 'v-1', { format: 'jks', password: 'short' }, 'www')).rejects.toMatchObject({
    status: 422,
    problem: { title: 'Invalid password' },
  });
});
