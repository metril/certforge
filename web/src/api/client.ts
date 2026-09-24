import createClient, { type Middleware } from 'openapi-fetch';
import type { paths } from './schema';
import { ApiError } from './errors';

export const API_BASE = '/api/v1';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
// A 401 on these means "not signed in yet"; route guards and forms handle it.
const QUIET_401 = new Set(['/auth/me', '/auth/login', '/setup/status', '/setup/complete']);

let csrfToken: string | null = null;
let onUnauthorized: () => void = defaultUnauthorized;
let redirecting = false;

// Adaptation (controller ruling, preflight A28): the default handler performs
// the actual sign-in redirect (a full navigation, not an SPA route push, so it
// also clears every in-memory cache — React Query's `me` included — along
// with the expired session state). Router-aware tasks may still override it
// with setUnauthorizedHandler.
function defaultUnauthorized(): void {
  if (typeof window === 'undefined') return;
  const next = encodeURIComponent(window.location.pathname + window.location.search);
  window.location.assign(`/login?next=${next}`);
}

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}
export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler;
}
export function resetUnauthorized(): void {
  redirecting = false;
}

// Clones stashed before fetch() consumes the request body, so a CSRF-flavoured
// 403 (preflight A28: a valid session with a stale cached token) can be
// retried once with a refreshed token. csrfRetried guards against looping if
// the retry also comes back 403.
const retryClones = new WeakMap<Request, Request>();
const csrfRetried = new WeakSet<Request>();

async function readDetail(response: Response): Promise<string | undefined> {
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('json')) return undefined;
  try {
    const body: unknown = await response.clone().json();
    const detail = (body as { detail?: unknown } | null)?.detail;
    return typeof detail === 'string' ? detail : undefined;
  } catch {
    return undefined;
  }
}

async function refreshCsrfToken(): Promise<string | null> {
  try {
    const res = await globalThis.fetch(`${globalThis.location?.origin ?? ''}${API_BASE}/auth/me`, {
      credentials: 'same-origin',
    });
    if (!res.ok) return null;
    const me = (await res.json()) as { csrfToken?: string };
    if (me.csrfToken) csrfToken = me.csrfToken;
    return me.csrfToken ?? null;
  } catch {
    return null;
  }
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return seconds;
  const when = Date.parse(value);
  return Number.isNaN(when) ? undefined : Math.max(0, Math.round((when - Date.now()) / 1000));
}

export const authMiddleware: Middleware = {
  onRequest({ request }) {
    if (!SAFE_METHODS.has(request.method)) {
      if (csrfToken) request.headers.set('X-CSRF-Token', csrfToken);
      retryClones.set(request, request.clone());
    }
    return request;
  },
  async onResponse({ request, response }) {
    let res = response;
    if (res.status === 403 && !csrfRetried.has(request)) {
      csrfRetried.add(request);
      const detail = await readDetail(res);
      if (detail && /csrf/i.test(detail)) {
        const refreshed = await refreshCsrfToken();
        const clone = retryClones.get(request);
        if (refreshed && clone) {
          clone.headers.set('X-CSRF-Token', refreshed);
          res = await globalThis.fetch(clone);
        }
      }
    }
    if (res.status === 401) {
      const path = new URL(request.url).pathname.slice(API_BASE.length);
      if (!QUIET_401.has(path) && !redirecting) {
        redirecting = true;
        csrfToken = null;
        onUnauthorized();
      }
    }
    return res;
  },
};

export const api = createClient<paths>({
  baseUrl: `${globalThis.location?.origin ?? ''}${API_BASE}`,
  credentials: 'same-origin',
  // Resolve fetch per call so test interceptors installed after import still apply.
  fetch: (request: Request) => globalThis.fetch(request),
});
api.use(authMiddleware);

export async function call<T>(pending: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  const { data, error, response } = await pending;
  if (error !== undefined || !response.ok) {
    const retryAfter = response.status === 503 ? parseRetryAfter(response.headers.get('retry-after')) : undefined;
    throw ApiError.from(response.status, error, retryAfter);
  }
  return data as T;
}
