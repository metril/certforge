import { http, HttpResponse } from 'msw';
import { act, screen } from '@testing-library/react';
import { focusManager } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { iso, makeAttempt, makeRateLedger, NOW, problem, url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { AttemptsTab } from './AttemptsTab';

const failedRateLedger = () =>
  makeAttempt({
    acmeErrorType: 'urn:ietf:params:acme:error:rateLimited',
    steps: [{ name: 'rate_ledger', status: 'failed', startedAt: iso(-0.01), finishedAt: iso(-0.0099), message: 'rate limit: duplicateCertsPerWeek, 5/5, retry at ' + iso(0.1) }],
  });

afterEach(() => focusManager.setFocused(undefined));

const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

it('polls a running attempt every 2 s, stops while hidden, and refetches once on return', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let calls = 0;
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => {
      calls++;
      return HttpResponse.json([makeAttempt({ outcome: 'running', finishedAt: undefined, acmeErrorType: undefined, retryAfter: undefined })]);
    }),
  );
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" />);
  await tick(50);
  expect(screen.getByText('Running')).toBeInTheDocument();
  const first = calls;

  await tick(2_050);
  expect(calls).toBe(first + 1);

  act(() => focusManager.setFocused(false));
  await tick(10_000);
  expect(calls).toBe(first + 1);

  act(() => focusManager.setFocused(true));
  await tick(50);
  expect(calls).toBe(first + 2);

  await tick(2_100);
  expect(calls).toBeGreaterThanOrEqual(first + 3);
});

it('slows to 30 s once no attempt is running', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let calls = 0;
  server.use(http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => (calls++, HttpResponse.json([makeAttempt()]))));
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" />);
  await tick(50);
  const first = calls;
  await tick(10_000);
  expect(calls).toBe(first);
  await tick(20_100);
  expect(calls).toBe(first + 1);
});

// Fix round 1 (review, Important #3): a failed fetch (403/500) used to fall
// through to the "No attempts yet" empty state with a Renew button —
// indistinguishable from a certificate that genuinely has none.
it('shows an error state, not the empty state, when the attempts fetch fails', async () => {
  server.use(http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => problem(500, 'boom')));
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" onRenew={() => {}} />);
  expect(await screen.findByText(/Couldn't load attempts\..*boom/)).toBeInTheDocument();
  expect(screen.queryByText('No attempts yet.')).toBeNull();
  expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
});

// Task 4: a failed rate_ledger step shows the current ledger usage under it,
// scoped by the certificate's CA and its own id.
it('shows ledger usage under a failed rate_ledger step', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => HttpResponse.json([failedRateLedger()])),
    http.get(url('/orgs/org-1/rate-ledger'), ({ request }) => {
      const q = new URL(request.url).searchParams;
      expect(q.get('ca')).toBe('ca-1');
      expect(q.get('certificate')).toBe('c-1');
      return HttpResponse.json(
        makeRateLedger({ items: [{ limit: 'duplicateCertsPerWeek', scope: 'www.example.com', count: 5, max: 5, windowSeconds: 604_800, resetsAt: iso(0.1) }] }),
      );
    }),
  );
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" caId="ca-1" />);
  expect(await screen.findByText('Duplicate certificates, 7 days')).toBeInTheDocument();
  expect(screen.getByText('5 / 5')).toBeInTheDocument();
  expect(screen.getByText(/resets in/)).toBeInTheDocument();
});

it('shows a Counted only chip for a staging (unenforced) CA', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => HttpResponse.json([failedRateLedger()])),
    http.get(url('/orgs/org-1/rate-ledger'), () => HttpResponse.json(makeRateLedger({ enforced: false }))),
  );
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" caId="ca-1" />);
  expect(await screen.findByText('Counted only')).toBeInTheDocument();
});

it('shows an error state with retry when the ledger fetch fails', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => HttpResponse.json([failedRateLedger()])),
    http.get(url('/orgs/org-1/rate-ledger'), () => problem(500, 'boom')),
  );
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" caId="ca-1" />);
  expect(await screen.findByText(/Couldn't load rate limits\..*boom/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
});

it('renders no ledger panel without a caId', async () => {
  server.use(http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => HttpResponse.json([failedRateLedger()])));
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" />);
  expect(await screen.findByText('Rate limits')).toBeInTheDocument();
  expect(screen.queryByRole('list', { name: 'Rate limits' })).toBeNull();
});
