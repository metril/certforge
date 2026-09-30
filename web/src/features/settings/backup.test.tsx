import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeAll, expect, it, vi } from 'vitest';
import type { BackupStatus } from '@/api/types';
import { saveBlob } from '@/lib/download';
import { server } from '@/test/server';
import { authHandlers, backupStatus, iso, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// Same precedent as audit.test.tsx: saveBlob clicks a real anchor, which
// jsdom can't navigate — mocked out so "downloads with server filename"
// only asserts what BackupSection hands it, not the DOM mechanics.
vi.mock('@/lib/download', async (orig) => ({ ...(await orig<typeof import('@/lib/download')>()), saveBlob: vi.fn() }));

// Same precedent as settings.test.tsx/keys.test.tsx: SettingsPage is the
// first thing to pull in RJSF/Ajv/tldts, a large one-time synchronous
// parse that can otherwise eat into a waitFor's own budget.
beforeAll(async () => {
  await import('./SettingsPage');
});

// The real backup settings-section schema (internal/backup's Settings),
// copied verbatim, same precedent as integrations.test.tsx's own vault/smtp
// schemas.
const backupSchema = {
  title: 'Backup',
  description: 'Scheduled backups of the whole database, encrypted with the active key-encryption key.',
  type: 'object',
  additionalProperties: false,
  properties: {
    kekEscrowConfirmed: {
      type: 'boolean',
      title: 'KEK escrow confirmed',
      description: 'Confirms the key-encryption key is stored safely outside this server.',
      default: false,
    },
    schedule: {
      type: 'string',
      title: 'Schedule',
      description: 'How often a backup is written automatically.',
      enum: ['off', 'daily', 'weekly'],
      default: 'off',
    },
    retainCount: {
      type: 'integer',
      title: 'Retain',
      description: 'Newest scheduled archives to keep in the directory.',
      minimum: 1,
      maximum: 90,
      default: 7,
    },
    directory: {
      type: 'string',
      title: 'Directory',
      description: 'Absolute path scheduled backups are written to. Required once a schedule is set.',
      maxLength: 1024,
    },
  },
};

function handlers(
  opts: {
    status?: BackupStatus;
    value?: Record<string, unknown>;
    onPut?: (b: Record<string, unknown>) => void;
    putError?: () => ReturnType<typeof problem>;
    onBackup?: () => Response;
    onStatus?: () => void;
  } = {},
) {
  const section = {
    section: 'backup',
    schema: backupSchema,
    value: opts.value ?? { kekEscrowConfirmed: false, schedule: 'off', retainCount: 7 },
    stored: null,
    storedSecrets: [] as string[],
  };
  return [
    http.get(url('/settings/backup'), () => HttpResponse.json(section)),
    http.put(url('/settings/backup'), async ({ request }) => {
      if (opts.putError) return opts.putError();
      const b = (await request.json()) as Record<string, unknown>;
      opts.onPut?.(b);
      return HttpResponse.json({ ...section, value: b });
    }),
    http.get(url('/backup/status'), () => {
      opts.onStatus?.();
      return HttpResponse.json(opts.status ?? backupStatus);
    }),
    http.post(url('/backup'), () =>
      opts.onBackup?.() ??
      new HttpResponse(new Blob(['data']), { headers: { 'Content-Disposition': 'attachment; filename="certforge-20260101T000000Z.cfbak"' } }),
    ),
  ];
}

it('status card shows last success, size, file and next', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers({
      status: {
        schedule: 'daily', escrowConfirmed: true, directory: '/var/backups',
        lastSuccessAt: iso(-1), lastFailureAt: null, lastError: null,
        lastSizeBytes: 33_554_432, lastFile: 'certforge-20260101T000000Z.cfbak', nextAt: iso(1),
      },
    }),
  );
  renderRoute('/settings/backup');
  expect(await screen.findByText('Escrow confirmed')).toBeInTheDocument();
  expect(screen.getByText('Succeeded')).toBeInTheDocument();
  expect(screen.getByText('32 MiB')).toBeInTheDocument();
  expect(screen.getByText('certforge-20260101T000000Z.cfbak')).toBeInTheDocument();
  expect(screen.getByText(/^in \d+ (h|min|d)$/)).toBeInTheDocument();
});

it('newer failure shows error', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers({
      status: {
        schedule: 'daily', escrowConfirmed: true, directory: '/var/backups',
        lastSuccessAt: iso(-3), lastFailureAt: iso(-1), lastError: 'no space left on device',
        lastSizeBytes: 33_554_432, lastFile: 'certforge-20251230T000000Z.cfbak', nextAt: iso(1),
      },
    }),
  );
  renderRoute('/settings/backup');
  expect(await screen.findByText('Failed')).toBeInTheDocument();
  expect(screen.getByText('no space left on device')).toBeInTheDocument();
  // A success has happened before, so size/file still show.
  expect(screen.getByText('32 MiB')).toBeInTheDocument();
});

it('never backed up', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers({ status: backupStatus }));
  renderRoute('/settings/backup');
  expect(await screen.findByText('Never')).toBeInTheDocument();
  expect(screen.getByText('Not scheduled')).toBeInTheDocument();
});

it('back up now disabled until escrow confirmed', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers({ status: { ...backupStatus, escrowConfirmed: false } }));
  const { user } = renderRoute('/settings/backup');
  const button = await screen.findByRole('button', { name: 'Back up now' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Confirm the KEK is stored safely first.');
});

it('back up now downloads with server filename', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers({ status: { ...backupStatus, escrowConfirmed: true } }));
  const { user } = renderRoute('/settings/backup');
  await screen.findByRole('button', { name: 'Back up now' });
  // The button re-renders from the escrow-tooltip-wrapped (disabled) form to
  // the bare enabled one once the status query resolves — a different
  // element at that JSX position, so the enabled one must be re-queried
  // rather than awaited on the same node reference.
  await waitFor(() => expect(screen.getByRole('button', { name: 'Back up now' })).toBeEnabled());
  await user.click(screen.getByRole('button', { name: 'Back up now' }));
  await waitFor(() => expect(saveBlob).toHaveBeenCalledWith(expect.any(Blob), 'certforge-20260101T000000Z.cfbak'));
  expect(await screen.findByText('Backup downloaded')).toBeInTheDocument();
});

it('409 toasts escrow', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers({
      status: { ...backupStatus, escrowConfirmed: true },
      onBackup: () => problem(409, 'confirm KEK escrow first'),
    }),
  );
  const { user } = renderRoute('/settings/backup');
  await screen.findByRole('button', { name: 'Back up now' });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Back up now' })).toBeEnabled());
  await user.click(screen.getByRole('button', { name: 'Back up now' }));
  expect(await screen.findByText('confirm KEK escrow first')).toBeInTheDocument();
});

it('needs settings:write', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    ...authHandlers({ authed: true }),
    ...handlers({ status: { ...backupStatus, escrowConfirmed: true } }),
  );
  const { user } = renderRoute('/settings/backup');
  const button = await screen.findByRole('button', { name: 'Back up now' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the settings:write permission');
});

it('schedule off hides retain and directory', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/backup');
  await screen.findByRole('radio', { name: 'Off' });
  expect(screen.queryByLabelText('Retain')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Directory')).not.toBeInTheDocument();
});

it('directory error maps inline', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    ...handlers({
      value: { kekEscrowConfirmed: false, schedule: 'daily', retainCount: 7, directory: '/var/backups' },
      putError: () => problem(422, 'directory is not a writable directory', {}, 'Invalid settings'),
    }),
  );
  const { user } = renderRoute('/settings/backup');
  const dirInput = await screen.findByLabelText('Directory');
  await user.clear(dirInput);
  await user.type(dirInput, '/var/backups2');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  const directoryField = screen.getByText('Directory').closest('div')!.parentElement!;
  expect(await within(directoryField).findByRole('alert')).toHaveTextContent('directory is not a writable directory');
});

it('escrow save refreshes status', async () => {
  let statusCalls = 0;
  server.use(...authHandlers({ authed: true }), ...handlers({ onStatus: () => statusCalls++ }));
  const { user } = renderRoute('/settings/backup');
  await screen.findByRole('switch', { name: 'KEK escrow confirmed' });
  const before = statusCalls;
  await user.click(screen.getByRole('switch', { name: 'KEK escrow confirmed' }));
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(statusCalls).toBeGreaterThan(before));
});

it('restore is tooltip only', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/backup');
  await screen.findByText('Backups');
  expect(screen.getByText('Restore')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /restore/i })).not.toBeInTheDocument();
  expect(document.querySelector('input[type="file"]')).toBeNull();
});
