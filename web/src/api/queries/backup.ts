import { queryOptions, type QueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { filenameFrom, saveBlob } from '@/lib/download';
import { api, call } from '../client';
import { ApiError, errorMessage } from '../errors';

export const backupStatusQuery = queryOptions({
  queryKey: ['backup-status'],
  queryFn: () => call(api.GET('/backup/status')),
});

/** Streams a fresh backup archive straight to a browser download; a blob
 * response is never cached (global constraints, "Secrets" — the archive is
 * key material). 409 ("confirm KEK escrow first") surfaces as an ApiError
 * with the server's own detail. */
export async function downloadBackup(): Promise<void> {
  const { data, error, response } = await api.POST('/backup', { parseAs: 'blob' });
  if (error !== undefined || !response.ok || !data) throw ApiError.from(response.status, error);
  saveBlob(data as Blob, filenameFrom(response, 'certforge-backup.cfbak'));
}

/** Downloads a fresh backup archive (task-7-brief), shared by
 * `BackupSection`'s own "Back up now" button and `CommandPalette`'s
 * "Settings: Back up now" entry. Toasts either way and refreshes
 * `['backup-status']` (a completed on-demand backup moves
 * `lastSuccessAt`/`lastSizeBytes`/`lastFile`; a 409 changes nothing
 * server-side, but the brief still calls for a refetch). Rethrows so a
 * caller that needs to react further — the palette navigates to Settings →
 * Backups on a 409 — can do so without re-toasting.
 *
 * Final review: lives here, in a plain query module, rather than in
 * `features/settings/BackupSection.tsx` where task 7 first wrote it —
 * `CommandPalette` importing it from `BackupSection` dragged
 * `SchemaSection` → `SchemaForm` (`@rjsf`, ~270 KB) into `_app`'s own static
 * import graph. Every authenticated page renders `_app`, so anything it
 * statically reaches loads eagerly regardless of `BackupSection`'s own
 * route being lazily loaded — `check-chunks.mjs`'s `_app` → `@rjsf`
 * reachability guard now fails the build if this regresses. */
export async function runBackup(qc: QueryClient): Promise<void> {
  try {
    await downloadBackup();
    toast.success('Backup downloaded');
  } catch (e) {
    toast.error(errorMessage(e));
    throw e;
  } finally {
    await qc.invalidateQueries({ queryKey: ['backup-status'] });
  }
}
