import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { url } from './fixtures';

// Adaptation (preflight C8): T4's AppShell test navigates to
// `/o/acme/certificates` without mocking `/certificates` or `/cas`; once
// T11 replaces the route stub with a page that actually fetches both, that
// test (and any other test that merely navigates through the certificates
// route without caring about its data) would fail on an unhandled request
// under `onUnhandledRequest: 'error'`. These empty-list defaults are
// restored by `server.resetHandlers()` after every test and are shadowed by
// any more specific `server.use(...)` handler a test adds for the same path.
export const server = setupServer(
  http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [] })),
  http.get(url('/orgs/:orgId/cas'), () => HttpResponse.json([])),
);
