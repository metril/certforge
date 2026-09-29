import { queryOptions } from '@tanstack/react-query';
import { filenameFrom, saveBlob } from '@/lib/download';
import { api, call } from '../client';
import { ApiError } from '../errors';

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
