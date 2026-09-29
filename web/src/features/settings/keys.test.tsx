import { http, HttpResponse } from 'msw';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, keysDone, keysRunning, keysStatic, meWith, NOW, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// useMe() needs router context (`/_app`), so this renders the real
// /settings/backup route (same precedent as agents.test.tsx), not the card
// standalone.
beforeAll(async () => {
  await import('./SettingsPage');
});

const backupSection = {
  section: 'backup',
  schema: { type: 'object', properties: { kekEscrowConfirmed: { type: 'boolean', title: 'KEK escrow confirmed' } } },
  value: { kekEscrowConfirmed: false },
  stored: null,
  storedSecrets: [],
};

beforeEach(() => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/settings/backup'), () => HttpResponse.json(backupSection)),
    http.put(url('/settings/backup'), () => HttpResponse.json({})),
  );
});

const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

it('static key basics', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json(keysStatic)));
  const { user } = renderRoute('/settings/backup');
  expect(await screen.findByText('Static')).toBeInTheDocument();
  expect(screen.queryByText(/vault\.example\.com/)).not.toBeInTheDocument();
  expect(screen.getByText('Canary OK')).toBeInTheDocument();
  expect(screen.getByText('None')).toBeInTheDocument();
  // No previous key and no rewrap has ever run: Rewrap now is disabled with
  // the keys.rewrapNoPrevious tooltip, not merely absent (batch 3 review,
  // Minor: actually hover and assert its text, not just `disabled`).
  const button = screen.getByRole('button', { name: 'Rewrap now' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Nothing to rewrap: no previous key is configured.');
});

it('transit shows address', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysRunning, rewrap: null })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Vault Transit')).toBeInTheDocument();
  expect(screen.getByText(keysRunning.vaultAddress!)).toBeInTheDocument();
});

it('previous key chips', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysRunning, rewrap: null })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('static · static-1')).toBeInTheDocument();
});

it('canary failed chip', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysStatic, canaryOk: false })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Canary failed')).toBeInTheDocument();
});

it('progress bars per table', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json(keysRunning)));
  const { container } = renderRoute('/settings/backup');
  await screen.findByText('Running');
  const bars = container.querySelectorAll('[role="progressbar"]');
  expect(bars).toHaveLength(7);
  for (const bar of bars) expect(bar).toHaveAttribute('aria-valuenow');
  // settings: scanned 10, rewrapped 10, remaining 0 -> "10 / 10"
  expect(screen.getByText('10 / 10')).toBeInTheDocument();
  // cas: scanned 4, rewrapped 2, remaining 2 -> "2 / 4"
  expect(screen.getByText('2 / 4')).toBeInTheDocument();
  expect(screen.getByText('Certificate versions')).toBeInTheDocument();
});

it('rewrap now starts and polls', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let getCalls = 0;
  server.use(
    http.get(url('/keys/status'), () => {
      getCalls++;
      return HttpResponse.json(keysDone);
    }),
    http.post(url('/keys/rewrap'), () => HttpResponse.json(keysRunning, { status: 202 })),
  );
  renderRoute('/settings/backup');
  for (let i = 0; i < 10 && !screen.queryByRole('button', { name: 'Rewrap now' }); i++) await tick(50);
  const button = screen.getByRole('button', { name: 'Rewrap now' });
  expect(button).toBeEnabled();
  // fireEvent (synchronous), not userEvent, under fake timers: userEvent's
  // own pointer-event simulation relies on real timers/RAF even with a
  // { delay: null } setup, which hangs once the clock is faked.
  await act(async () => fireEvent.click(button));
  await tick(50);
  expect(screen.getByText('Running')).toBeInTheDocument();
  const afterStart = getCalls;
  await tick(5_050);
  expect(getCalls).toBeGreaterThan(afterStart);
});

it('polls only while running', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let getCalls = 0;
  server.use(http.get(url('/keys/status'), () => { getCalls++; return HttpResponse.json(keysDone); }));
  renderRoute('/settings/backup');
  for (let i = 0; i < 10 && !screen.queryByText('Finished'); i++) await tick(50);
  expect(screen.getByText('Finished')).toBeInTheDocument();
  const first = getCalls;
  await tick(10_000);
  expect(getCalls).toBe(first);
});

it('409 toasts running', async () => {
  let getCalls = 0;
  server.use(
    http.get(url('/keys/status'), () => { getCalls++; return HttpResponse.json(keysDone); }),
    http.post(url('/keys/rewrap'), () => problem(409, 'a rewrap is already running')),
  );
  const { user } = renderRoute('/settings/backup');
  const button = await screen.findByRole('button', { name: 'Rewrap now' });
  const before = getCalls;
  await user.click(button);
  expect(await screen.findByText('A rewrap is already running')).toBeInTheDocument();
  await waitFor(() => expect(getCalls).toBeGreaterThan(before));
});

it('rewrap disabled while running', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json(keysRunning)));
  renderRoute('/settings/backup');
  expect(await screen.findByRole('button', { name: 'Rewrap now' })).toBeDisabled();
});

it('needs settings:write', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    http.get(url('/keys/status'), () => HttpResponse.json(keysDone)),
  );
  const { user } = renderRoute('/settings/backup');
  const button = await screen.findByRole('button', { name: 'Rewrap now' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the settings:write permission');
});

it('error state retries', async () => {
  let calls = 0;
  server.use(
    http.get(url('/keys/status'), () => {
      calls++;
      return calls === 1 ? problem(500, 'boom') : HttpResponse.json(keysStatic);
    }),
  );
  const { user } = renderRoute('/settings/backup');
  expect(await screen.findByText(/Couldn't load.*boom/)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Retry' }));
  expect(await screen.findByText('Static')).toBeInTheDocument();
});
