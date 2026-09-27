import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { ImportResult } from '../types';

export type ImportBody = { archive: File; caId: string; dryRun: boolean };

// openapi-typescript types `format: binary` as `string`, so `body` here is a
// cast placeholder: openapi-fetch skips its own JSON body handling and
// bodySerializer builds the real multipart FormData.
export async function importCertificates(orgId: string, { archive, caId, dryRun }: ImportBody): Promise<ImportResult> {
  const fd = new FormData();
  fd.append('archive', archive);
  fd.append('caId', caId);
  fd.append('dryRun', dryRun ? 'true' : 'false');
  return call(
    api.POST('/orgs/{orgId}/certificates/import', {
      params: { path: { orgId } },
      body: {} as never,
      bodySerializer: () => fd,
    }),
  );
}

export function useImportCertificates(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ImportBody) => importCertificates(orgId, body),
    meta: { silent: true },
    onSuccess: (_data, vars) => {
      if (!vars.dryRun) qc.invalidateQueries({ queryKey: ['certs', orgId] });
    },
  });
}
