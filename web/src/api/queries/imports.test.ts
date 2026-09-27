import { createElement } from 'react';
import { http, HttpResponse } from 'msw';
import { QueryClientProvider } from '@tanstack/react-query';
import { renderHook, waitFor } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { makeImportResult, url } from '@/test/fixtures';
import { makeQueryClient } from '@/lib/queryClient';
import { useImportCertificates } from './imports';

// The multipart-body shape (archive/caId/dryRun as seen by the server) is
// covered separately in imports.multipart.test.ts, which needs a plain node
// environment — see that file's comment.
it('create (non-dry-run) invalidates certs', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/import'), () => HttpResponse.json(makeImportResult({ dryRun: false }))));
  const qc = makeQueryClient({ test: true });
  qc.setQueryData(['certs', 'org-1'], []);
  const { result } = renderHook(() => useImportCertificates('org-1'), {
    wrapper: ({ children }) => createElement(QueryClientProvider, { client: qc }, children),
  });
  const archive = new File(['x'], 'a.tar');
  await result.current.mutateAsync({ archive, caId: 'ca-1', dryRun: false });
  await waitFor(() => expect(qc.getQueryState(['certs', 'org-1'])?.isInvalidated).toBe(true));
});
