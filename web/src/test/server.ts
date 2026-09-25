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
//
// Same reasoning, Task 16: the `$id/$tab` route's stub is replaced by
// `CertificateDetail`, which always mounts `ManualDnsCard` (it renders
// nothing without pending records — a controller ruling, so the page
// doesn't need its own "is this a manual-dns cert" check) and always reads
// `attemptsQuery` itself (to decide whether to poll the certificate at the
// live 2s rate, not just 30s — a running attempt matters even while the
// user is looking at another tab). Existing tests that merely navigate into
// a certificate's detail route (e.g. the wizard, after issuing) don't mock
// `.../manual-dns` or `.../attempts` themselves.
//
// Task 17: the `/o/$org/overview` route's stub is replaced by
// `OverviewPage`, which fetches every certificate and `/readyz` on every
// render — earlier tests (Tasks 3 and 4) that merely navigate through this
// route don't mock either. `server.use()` in a given test still wins over
// these defaults (msw tries handlers most-recently-added first).
export const server = setupServer(
  http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [], nextCursor: null })),
  http.get(url('/orgs/:orgId/cas'), () => HttpResponse.json([])),
  http.get(url('/orgs/:orgId/certificates/:id/manual-dns'), () => HttpResponse.json([])),
  http.get(url('/orgs/:orgId/certificates/:id/attempts'), () => HttpResponse.json([])),
  http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok' } })),
);
