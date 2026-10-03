import { http, HttpResponse } from 'msw';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
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
  schema: { type: 'object', properties: { retainCount: { type: 'integer', title: 'Retain' } } },
  value: { retainCount: 7 },
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

it('quiet row when nothing needs attention', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json(keysStatic)));
  const { user } = renderRoute('/settings/backup');
  expect(await screen.findByText('Key check OK')).toBeInTheDocument();
  expect(screen.queryByText('Static')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Re-encrypt now' })).not.toBeInTheDocument();
  expect(screen.queryByRole('list', { name: 'Key replacement steps' })).not.toBeInTheDocument();
  await user.tab();
  await user.hover(screen.getAllByRole('button', { name: 'Help' }).at(-1)!);
  expect(await screen.findByRole('tooltip')).toHaveTextContent(
    "Set in the server's environment. Needed to restore any backup. To replace it, set the new key as CF_KEK, move the old one to CF_KEK_PREVIOUS, and restart.",
  );
});

it('full card for an older key with no re-encryption yet', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysStatic, previous: [{ kind: 'static', kekId: 'static-0' }] })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Static')).toBeInTheDocument();
  expect(screen.getByText('Key check OK')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Re-encrypt now' })).toBeEnabled();
  expect(stepOf('Re-encrypting')).toHaveAttribute('aria-current', 'step');
});

it('full card with the disabled button and tooltip when only the key check fails', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysStatic, canaryOk: false })));
  const { user } = renderRoute('/settings/backup');
  const button = await screen.findByRole('button', { name: 'Re-encrypt now' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Nothing to re-encrypt: no older key is set.');
  expect(stepOf('New key set')).toHaveAttribute('aria-current', 'step');
});

function stepOf(label: string | RegExp) {
  const list = screen.getByRole('list', { name: 'Key replacement steps' });
  return within(list).getByText(label).closest('li')!;
}

it('stepper: re-encrypting shows the remaining count', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json(keysRunning)));
  renderRoute('/settings/backup');
  await screen.findByText('Running');
  expect(stepOf('New key set').querySelector('svg')).not.toBeNull();
  expect(stepOf('Re-encrypting (25 left)')).toHaveAttribute('aria-current', 'step');
  expect(stepOf('Remove the old key')).not.toHaveAttribute('aria-current');
});

it('stepper: remove the old key once nothing is left', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json(keysDone)));
  const { user } = renderRoute('/settings/backup');
  await screen.findByText('Finished');
  expect(stepOf('Remove the old key')).toHaveAttribute('aria-current', 'step');
  expect(stepOf('Re-encrypting').querySelector('svg')).not.toBeNull();
  await user.hover(within(stepOf('Remove the old key')).getByRole('button', { name: 'Help' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Delete CF_KEK_PREVIOUS from the environment and restart.');
});

it('stepper: a finished run for another key does not suggest removing the old key', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysDone, rewrap: { ...keysDone.rewrap!, activeKekId: 'older-key' } })));
  renderRoute('/settings/backup');
  await screen.findByText('Finished');
  expect(stepOf('Re-encrypting')).toHaveAttribute('aria-current', 'step');
  expect(stepOf('Remove the old key')).not.toHaveAttribute('aria-current');
});

it('stepper: a finished run for the active key moves to removing the old key', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysDone, rewrap: { ...keysDone.rewrap!, activeKekId: keysDone.kekId } })));
  renderRoute('/settings/backup');
  await screen.findByText('Finished');
  expect(stepOf('Remove the old key')).toHaveAttribute('aria-current', 'step');
});

it('a failed re-encryption with nothing left and no older key shows the full card with the error', async () => {
  server.use(
    http.get(url('/keys/status'), () =>
      HttpResponse.json({ ...keysDone, previous: [], rewrap: { ...keysDone.rewrap!, error: 'vault unreachable' } }),
    ),
  );
  renderRoute('/settings/backup');
  expect(await screen.findByText('Failed')).toBeInTheDocument();
  expect(screen.getByText('vault unreachable')).toBeInTheDocument();
  expect(stepOf('Re-encrypting')).toHaveAttribute('aria-current', 'step');
});

it('unfinished re-encryption without an older key still shows the card', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysRunning, previous: [], rewrap: { ...keysRunning.rewrap!, running: false } })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Finished')).toBeInTheDocument();
  expect(stepOf('Re-encrypting (25 left)')).toHaveAttribute('aria-current', 'step');
});

it('transit shows address', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysRunning, rewrap: null })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Vault Transit')).toBeInTheDocument();
  expect(screen.getByText(keysRunning.vaultAddress!)).toBeInTheDocument();
});

it('transit without an address (read-only caller) still shows the kind', async () => {
  const noAddress = { ...keysRunning, vaultAddress: undefined };
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...noAddress, rewrap: null })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Vault Transit')).toBeInTheDocument();
  expect(screen.queryByText(keysRunning.vaultAddress!)).not.toBeInTheDocument();
});

it('previous key chips', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysRunning, rewrap: null })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('static · static-1')).toBeInTheDocument();
});

it('key check failed chip', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json({ ...keysStatic, canaryOk: false })));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Key check failed')).toBeInTheDocument();
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
  for (let i = 0; i < 10 && !screen.queryByRole('button', { name: 'Re-encrypt now' }); i++) await tick(50);
  const button = screen.getByRole('button', { name: 'Re-encrypt now' });
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
  const button = await screen.findByRole('button', { name: 'Re-encrypt now' });
  const before = getCalls;
  await user.click(button);
  expect(await screen.findByText('Re-encryption is already running')).toBeInTheDocument();
  await waitFor(() => expect(getCalls).toBeGreaterThan(before));
});

it('rewrap disabled while running', async () => {
  server.use(http.get(url('/keys/status'), () => HttpResponse.json(keysRunning)));
  renderRoute('/settings/backup');
  expect(await screen.findByRole('button', { name: 'Re-encrypt now' })).toBeDisabled();
});

it('needs settings:write', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    http.get(url('/keys/status'), () => HttpResponse.json(keysDone)),
  );
  const { user } = renderRoute('/settings/backup');
  const button = await screen.findByRole('button', { name: 'Re-encrypt now' });
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
  expect(await screen.findByText('Key check OK')).toBeInTheDocument();
});
