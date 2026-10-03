import type { ReactElement } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { expect, it, vi } from 'vitest';
import { Providers } from '@/app/Providers';
import { server } from '@/test/server';
import { iso, makeAttempt, NOW, url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { AttemptLogViewer } from './AttemptLogViewer';

// The list omits logs; the viewer loads the one it shows, on demand.
const attemptUrl = url('/orgs/org-1/certificates/c-1/attempts/a-1');
const fullLog = () => http.get(attemptUrl, () => HttpResponse.json(makeAttempt()));
const noLog = (a = {}) => makeAttempt({ log: undefined, ...a });

it('opens with the failing step expanded, one-line explanation, and a collapsed raw log', async () => {
  server.use(fullLog());
  const { user } = renderUI(<AttemptLogViewer orgId="org-1" certId="c-1" attempt={noLog()} defaultOpen />);
  expect(screen.getByText('Failed')).toBeInTheDocument();
  expect(screen.getByText('A DNS lookup failed during validation.')).toBeInTheDocument();
  expect(screen.getByText('NXDOMAIN looking up TXT for _acme-challenge.www.example.com')).toBeInTheDocument();
  expect(screen.queryByText('requesting order')).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Raw log' }));
  expect(await screen.findByText('requesting order')).toBeInTheDocument();
  await user.type(screen.getByLabelText('Search log'), 'nxdomain');
  expect(screen.queryByText('requesting order')).toBeNull();
  expect(screen.getByText('error: NXDOMAIN looking up TXT')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Copy log' }));
  expect(await navigator.clipboard.readText()).toContain('presenting dns-01');
});

// Fix round 1 (review, Important #1): StepRow used to read `expanded` into
// state only at mount, so a step that turns from running to failed on a
// later render (same key, same instance) kept its message hidden with no
// way to open it (the toggle only renders while `!expanded`).
it("shows a step's message once it turns from running to failed on a later render", () => {
  const running = makeAttempt({
    outcome: 'running',
    finishedAt: undefined,
    acmeErrorType: undefined,
    retryAfter: undefined,
    steps: [
      { name: 'account', status: 'success', startedAt: iso(-0.01), finishedAt: iso(-0.0099) },
      { name: 'challenge www.example.com', status: 'running', startedAt: iso(-0.0098) },
    ],
  });
  const { rerender, queryClient } = renderUI(<AttemptLogViewer orgId="org-1" certId="c-1" attempt={running} defaultOpen />);
  const wrap = (ui: ReactElement) => <Providers queryClient={queryClient}>{ui}</Providers>;
  expect(screen.queryByText(/NXDOMAIN/)).toBeNull();

  const failed = makeAttempt({
    steps: [
      { name: 'account', status: 'success', startedAt: iso(-0.01), finishedAt: iso(-0.0099) },
      {
        name: 'challenge www.example.com',
        status: 'failed',
        startedAt: iso(-0.0098),
        finishedAt: iso(-0.009),
        message: 'NXDOMAIN looking up TXT for _acme-challenge.www.example.com',
      },
    ],
  });
  rerender(wrap(<AttemptLogViewer orgId="org-1" certId="c-1" attempt={failed} defaultOpen />));
  expect(screen.getByText('NXDOMAIN looking up TXT for _acme-challenge.www.example.com')).toBeInTheDocument();
});

// Task 4: the server's real step names, `caa` and `rate_ledger`, get
// readable labels; every other step name passes through unchanged.
it('labels caa and rate limits', () => {
  renderUI(
    <AttemptLogViewer
      orgId="org-1"
      certId="c-1"
      attempt={makeAttempt({
        steps: [
          { name: 'caa', status: 'success', startedAt: iso(-0.01), finishedAt: iso(-0.0099) },
          { name: 'rate_ledger', status: 'success', startedAt: iso(-0.0099), finishedAt: iso(-0.0098) },
          { name: 'account', status: 'success', startedAt: iso(-0.0098), finishedAt: iso(-0.0097) },
        ],
      })}
      defaultOpen
    />,
  );
  expect(screen.getByText('CAA check')).toBeInTheDocument();
  expect(screen.getByText('Rate limits')).toBeInTheDocument();
  expect(screen.getByText('account')).toBeInTheDocument();
  expect(screen.queryByText('caa')).toBeNull();
  expect(screen.queryByText('rate_ledger')).toBeNull();
});

it('skipped caa shows its reason inline, without a details toggle', () => {
  renderUI(
    <AttemptLogViewer
      orgId="org-1"
      certId="c-1"
      attempt={makeAttempt({
        outcome: 'success',
        acmeErrorType: undefined,
        retryAfter: undefined,
        steps: [{ name: 'caa', status: 'skipped', startedAt: iso(-0.01), finishedAt: iso(-0.0099), message: 'disabled in settings' }],
      })}
      defaultOpen
    />,
  );
  expect(screen.getByText('disabled in settings')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Details' })).toBeNull();
});

it('failed caa stays expanded with its detail text', () => {
  renderUI(
    <AttemptLogViewer
      orgId="org-1"
      certId="c-1"
      attempt={makeAttempt({
        acmeErrorType: 'urn:ietf:params:acme:error:caa',
        steps: [
          {
            name: 'caa',
            status: 'failed',
            startedAt: iso(-0.01),
            finishedAt: iso(-0.0099),
            message: 'CAA at example.com allows other-ca.example; the CA identifies as letsencrypt.org. Add: example.com CAA 0 issue "letsencrypt.org"',
          },
        ],
      })}
      defaultOpen
    />,
  );
  expect(screen.getByText('CAA check')).toBeInTheDocument();
  expect(screen.getByText(/CAA at example\.com allows other-ca\.example/)).toBeInTheDocument();
});

// Task 4 (R12 deviation, 5a-facts.md): a private-CA attempt records account,
// verify/challenge, caa and rate_ledger as skipped with "not used by
// private CAs" — no component change, StepRow's existing skipped handling
// already renders each one this way.
it('private CA skipped steps', () => {
  renderUI(
    <AttemptLogViewer
      orgId="org-1"
      certId="c-1"
      attempt={makeAttempt({
        outcome: 'success',
        acmeErrorType: undefined,
        retryAfter: undefined,
        steps: [
          { name: 'account', status: 'skipped', startedAt: iso(-0.01), finishedAt: iso(-0.0099), message: 'not used by private CAs' },
          { name: 'challenge www.example.com', status: 'skipped', startedAt: iso(-0.0099), finishedAt: iso(-0.0098), message: 'not used by private CAs' },
          { name: 'caa', status: 'skipped', startedAt: iso(-0.0098), finishedAt: iso(-0.0097), message: 'not used by private CAs' },
          { name: 'rate_ledger', status: 'skipped', startedAt: iso(-0.0097), finishedAt: iso(-0.0096), message: 'not used by private CAs' },
        ],
      })}
      defaultOpen
    />,
  );
  expect(screen.getAllByText('not used by private CAs')).toHaveLength(4);
  expect(screen.getAllByText('Skipped:', { selector: '.sr-only' })).toHaveLength(4);
  expect(screen.getByText('CAA check')).toBeInTheDocument();
  expect(screen.getByText('Rate limits')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Details' })).toBeNull();
});

it('guards Copy log when the Clipboard API is unavailable', async () => {
  const original = navigator.clipboard;
  server.use(fullLog());
  try {
    const { user } = renderUI(<AttemptLogViewer orgId="org-1" certId="c-1" attempt={makeAttempt()} defaultOpen />);
    await user.click(screen.getByRole('button', { name: 'Raw log' }));
    // renderUI's userEvent.setup() installs its own navigator.clipboard stub,
    // so the override has to happen after render, not before (same pattern
    // as controls.test.tsx's CopyField clipboard tests).
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    await user.click(screen.getByRole('button', { name: 'Copy log' }));
    expect(await screen.findByText('Copy failed')).toBeInTheDocument();
  } finally {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: original });
  }
});

it('fetches the log only once Raw log is opened', async () => {
  let calls = 0;
  server.use(http.get(attemptUrl, () => (calls++, HttpResponse.json(makeAttempt()))));
  const { user } = renderUI(<AttemptLogViewer orgId="org-1" certId="c-1" attempt={noLog()} defaultOpen />);
  expect(calls).toBe(0);
  await user.click(screen.getByRole('button', { name: 'Raw log' }));
  expect(await screen.findByText('requesting order')).toBeInTheDocument();
  expect(calls).toBe(1);
});

it('tails the log every 2 s while the attempt runs', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let calls = 0;
  server.use(http.get(attemptUrl, () => (calls++, HttpResponse.json(makeAttempt({ outcome: 'running', log: `line ${calls}` })))));
  renderUI(<AttemptLogViewer orgId="org-1" certId="c-1" attempt={noLog({ outcome: 'running', finishedAt: undefined })} defaultOpen />);
  fireEvent.click(screen.getByRole('button', { name: 'Raw log' }));
  await act(async () => { await vi.advanceTimersByTimeAsync(50); });
  const first = calls;
  expect(first).toBeGreaterThan(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(2_050); });
  expect(calls).toBe(first + 1);
  expect(screen.getByText(`line ${first + 1}`)).toBeInTheDocument();
});

it('fetches the final log once the fetched attempt finishes, then stops polling', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let calls = 0;
  server.use(
    http.get(attemptUrl, () => {
      calls++;
      return HttpResponse.json(calls < 3 ? makeAttempt({ outcome: 'running', log: `line ${calls}` }) : makeAttempt({ log: 'final line' }));
    }),
  );
  // The list's copy still says running; only the fetched attempt knows it finished.
  renderUI(<AttemptLogViewer orgId="org-1" certId="c-1" attempt={noLog({ outcome: 'running', finishedAt: undefined })} defaultOpen />);
  fireEvent.click(screen.getByRole('button', { name: 'Raw log' }));
  await act(async () => { await vi.advanceTimersByTimeAsync(50); });
  await act(async () => { await vi.advanceTimersByTimeAsync(4_200); });
  expect(calls).toBe(3);
  expect(screen.getByText('final line')).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(calls).toBe(3);
});

const bigLog = Array.from({ length: 1234 }, (_, i) => `entry ${i + 1}`).join('\n');
const openBigLog = async () => {
  server.use(http.get(attemptUrl, () => HttpResponse.json(makeAttempt({ log: bigLog }))));
  const { user } = renderUI(<AttemptLogViewer orgId="org-1" certId="c-1" attempt={noLog()} defaultOpen />);
  await user.click(screen.getByRole('button', { name: 'Raw log' }));
  await screen.findByText('entry 1234');
  return user;
};

it('renders only the last 500 lines of a long log, then shows all and returns to the tail', async () => {
  const user = await openBigLog();
  expect(screen.queryByText('entry 734')).toBeNull();
  expect(screen.getByText('entry 735')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Show all 1,234 lines' }));
  expect(screen.getByText('entry 1')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Show last 500 lines' }));
  expect(screen.queryByText('entry 1')).toBeNull();
  expect(screen.getByText('entry 1234')).toBeInTheDocument();
});

it('the search covers lines outside the rendered tail', async () => {
  const user = await openBigLog();
  expect(screen.queryByText('entry 7')).toBeNull();
  await user.type(screen.getByLabelText('Search log'), 'entry 7');
  expect(screen.getByText('entry 7')).toBeInTheDocument();
  expect(screen.queryByText('entry 1234')).toBeNull();
});
