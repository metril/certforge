import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { ReactNode } from 'react';
import { expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { url } from '@/test/fixtures';
import { useRevokeVersion } from './certificates';

it('revoking a version also invalidates the certificate and its attempts', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/revoke'), () => new HttpResponse(null, { status: 204 })));
  const qc = new QueryClient();
  const spy = vi.spyOn(qc, 'invalidateQueries');
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
  const { result } = renderHook(() => useRevokeVersion('org-1', 'c-1'), { wrapper });
  await act(async () => {
    result.current.mutate({ vid: 'v-1', reason: 'unspecified' });
  });
  await waitFor(() => expect(result.current.isSuccess).toBe(true));
  const keys = spy.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey));
  expect(keys).toContain(JSON.stringify(['certs', 'org-1']));
  expect(keys).toContain(JSON.stringify(['attempts', 'org-1', 'c-1']));
});
