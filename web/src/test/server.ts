import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { issuanceSettingsSchema, keysStatic, makeImportResult, makeRateLedger, url } from './fixtures';

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
//
// Task 9: `AuditPage` fetches `/users` unconditionally (for the Actor
// filter and to resolve actor names) whenever the caller can read them,
// which every default `me` fixture (admin) can — most audit tests don't
// care about actor names and don't mock it themselves.
export const server = setupServer(
  http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [], nextCursor: null })),
  http.get(url('/orgs/:orgId/cas'), () => HttpResponse.json([])),
  http.get(url('/orgs/:orgId/certificates/:id/manual-dns'), () => HttpResponse.json([])),
  http.get(url('/orgs/:orgId/certificates/:id/attempts'), () => HttpResponse.json([])),
  http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok' } })),
  http.get(url('/auth/methods'), () => HttpResponse.json({ oidcEnabled: false, localEnabled: true })),
  http.get(url('/certificates'), () => HttpResponse.json({ items: [], nextCursor: null })),
  http.get(url('/audit'), () => HttpResponse.json({ items: [], nextCursor: null })),
  http.get(url('/users'), () => HttpResponse.json({ items: [] })),
  http.get(url('/audit/verify'), () =>
    HttpResponse.json({ ok: true, count: 0, brokenAtId: null, checkedAt: '2026-09-24T12:00:00Z', headHash: '' }),
  ),
  // Phase 3B: Overview, the clients list, the palette and Settings → Agents
  // fetch these on every render; tests that care override them.
  http.get(url('/orgs/:orgId/clients'), () => HttpResponse.json({ items: [], nextCursor: null })),
  http.get(url('/clients'), () => HttpResponse.json({ items: [], nextCursor: null })),
  http.get(url('/orgs/:orgId/sites'), () => HttpResponse.json({ items: [] })),
  http.get(url('/orgs/:orgId/layouts'), () => HttpResponse.json({ items: [] })),
  http.get(url('/orgs/:orgId/deploy-targets'), () => HttpResponse.json({ items: [] })),
  http.get(url('/orgs/:orgId/hooks'), () => HttpResponse.json({ items: [] })),
  http.get(url('/orgs/:orgId/certificates/:id/deployments'), () => HttpResponse.json({ items: [] })),
  http.get(url('/agents/ca'), () => HttpResponse.json({ items: [], listener: { caId: null, names: [], notAfter: null } })),
  http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [], notifiers: [], signers: [] })),
  // Task 1 (Phase 4B): the issuance settings section, the rate ledger, and a
  // dry-run import preview — tests that merely navigate through these
  // routes without caring about their data don't mock them themselves.
  http.get(url('/settings/issuance'), () =>
    HttpResponse.json({
      section: 'issuance',
      schema: issuanceSettingsSchema,
      value: { caaCheck: true, rateLimits: { certsPerRegisteredDomainPerWeek: 50, duplicateCertsPerWeek: 5, failedValidationsPerHour: 5, newOrdersPer3Hours: 300 } },
      stored: null,
      storedSecrets: [],
    }),
  ),
  http.get(url('/orgs/:orgId/rate-ledger'), () => HttpResponse.json(makeRateLedger())),
  http.post(url('/orgs/:orgId/certificates/import'), () => HttpResponse.json(makeImportResult())),
  // Phase 5B Task 1: the keys card, a deploy target's server grants, and
  // the Vault settings section — tests that merely navigate through these
  // routes don't mock them themselves.
  http.get(url('/keys/status'), () => HttpResponse.json(keysStatic)),
  http.get(url('/orgs/:orgId/deploy-targets/:id/grants'), () => HttpResponse.json([])),
  http.get(url('/settings/vault'), () =>
    HttpResponse.json({
      section: 'vault',
      schema: {},
      value: { authMethod: 'token', timeoutSeconds: 10 },
      stored: null,
      storedSecrets: [],
    }),
  ),
);
