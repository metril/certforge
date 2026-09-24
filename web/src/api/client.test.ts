import { http, HttpResponse } from 'msw';
import { beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { csrfProblem, me, problem, url } from '@/test/fixtures';
import { api, call, defaultUnauthorized, resetUnauthorized, setCsrfToken, setUnauthorizedHandler } from './client';
import { ApiError, errorMessage } from './errors';

beforeEach(() => {
  resetUnauthorized();
  setCsrfToken(null);
});

it('sends X-CSRF-Token only on mutating requests', async () => {
  const seen: Record<string, string | null> = {};
  server.use(
    http.get(url('/orgs'), ({ request }) => {
      seen.get = request.headers.get('X-CSRF-Token');
      return HttpResponse.json({ items: [] });
    }),
    http.post(url('/auth/logout'), ({ request }) => {
      seen.post = request.headers.get('X-CSRF-Token');
      return new HttpResponse(null, { status: 204 });
    }),
  );
  setCsrfToken('tok');
  await call(api.GET('/orgs'));
  await call(api.POST('/auth/logout'));
  expect(seen).toEqual({ get: null, post: 'tok' });
});

it('turns problem+json into ApiError with the detail as message', async () => {
  server.use(
    http.get(url('/orgs'), () =>
      HttpResponse.json(
        { type: 'about:blank', title: 'Conflict', status: 409, detail: 'CA is used by 2 certificates' },
        { status: 409, headers: { 'Content-Type': 'application/problem+json' } },
      ),
    ),
  );
  const err = await call(api.GET('/orgs')).catch((e: unknown) => e);
  expect(err).toBeInstanceOf(ApiError);
  expect((err as ApiError).status).toBe(409);
  expect((err as ApiError).message).toBe('CA is used by 2 certificates');
});

it('calls the 401 handler once for concurrent failures and never for /auth/me', async () => {
  const onUnauthorized = vi.fn();
  setUnauthorizedHandler(onUnauthorized);
  const denied = () => HttpResponse.json({ title: 'Unauthorized', status: 401 }, { status: 401 });
  server.use(http.get(url('/orgs'), denied), http.get(url('/auth/me'), denied));
  await call(api.GET('/auth/me')).catch(() => {});
  expect(onUnauthorized).not.toHaveBeenCalled();
  await Promise.all([call(api.GET('/orgs')).catch(() => {}), call(api.GET('/orgs')).catch(() => {})]);
  expect(onUnauthorized).toHaveBeenCalledTimes(1);
});

// Adaptation (controller ruling, preflight A28): authn.Middleware 403s a
// mutating request whenever its cached CSRF token is stale; the client
// refreshes /auth/me once and retries with the fresh token. csrfProblem()
// uses the real title and detail internal/authn/middleware.go sends.
it('retries once after a CSRF-flavoured 403, refreshing the token first', async () => {
  setCsrfToken('stale');
  let logoutCalls = 0;
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(me)),
    http.post(url('/auth/logout'), ({ request }) => {
      logoutCalls += 1;
      if (request.headers.get('X-CSRF-Token') !== me.csrfToken) return csrfProblem();
      return new HttpResponse(null, { status: 204 });
    }),
  );
  await call(api.POST('/auth/logout'));
  expect(logoutCalls).toBe(2);
});

// The client matches on title OR detail: a reworded detail that drops the
// word "csrf" (title alone still says so) must still trigger the retry.
it('retries on a CSRF 403 whose detail does not mention CSRF, matching the title instead', async () => {
  setCsrfToken('stale');
  let logoutCalls = 0;
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(me)),
    http.post(url('/auth/logout'), ({ request }) => {
      logoutCalls += 1;
      if (request.headers.get('X-CSRF-Token') !== me.csrfToken) {
        return problem(403, 'Header missing or stale.', {}, 'CSRF token missing or invalid');
      }
      return new HttpResponse(null, { status: 204 });
    }),
  );
  await call(api.POST('/auth/logout'));
  expect(logoutCalls).toBe(2);
});

it('does not loop when the retried request is also rejected', async () => {
  setCsrfToken('stale');
  let logoutCalls = 0;
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(me)),
    http.post(url('/auth/logout'), () => {
      logoutCalls += 1;
      return csrfProblem();
    }),
  );
  const err = await call(api.POST('/auth/logout')).catch((e: unknown) => e);
  expect(logoutCalls).toBe(2);
  expect((err as ApiError).status).toBe(403);
});

it('surfaces the problem detail on a 413', async () => {
  server.use(http.get(url('/orgs'), () => problem(413, 'Request body exceeds 1 MiB.')));
  const err = await call(api.GET('/orgs')).catch((e: unknown) => e);
  expect(err).toBeInstanceOf(ApiError);
  expect((err as ApiError).status).toBe(413);
  expect((err as ApiError).message).toBe('Request body exceeds 1 MiB.');
});

it('defaultUnauthorized redirects to /login with the current path, search, and hash, but not from /login itself', () => {
  // jsdom's window.location.assign isn't a configurable property vi.spyOn can
  // wrap directly, so the whole location object is swapped out for the test.
  const original = window.location;
  const assign = vi.fn();
  Object.defineProperty(window, 'location', {
    value: { pathname: '/o/acme/certificates', search: '?tab=versions', hash: '#v-2', assign },
    configurable: true,
  });
  defaultUnauthorized();
  expect(assign).toHaveBeenCalledWith('/login?next=%2Fo%2Facme%2Fcertificates%3Ftab%3Dversions%23v-2');

  assign.mockClear();
  Object.defineProperty(window, 'location', {
    value: { pathname: '/login', search: '', hash: '', assign },
    configurable: true,
  });
  defaultUnauthorized();
  expect(assign).not.toHaveBeenCalled();

  Object.defineProperty(window, 'location', { value: original, configurable: true });
});

it('surfaces the Retry-After header on a 503', async () => {
  server.use(http.get(url('/orgs'), () => problem(503, 'Service busy.', { 'Retry-After': '5' })));
  const err = await call(api.GET('/orgs')).catch((e: unknown) => e);
  expect(err).toBeInstanceOf(ApiError);
  expect((err as ApiError).status).toBe(503);
  expect((err as ApiError).retryAfter).toBe(5);
  expect(errorMessage(err)).toBe('Service busy. Retry in 5s.');
});
