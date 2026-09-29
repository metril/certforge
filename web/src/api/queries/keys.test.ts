import { createElement } from 'react';
import { http, HttpResponse } from 'msw';
import { QueryClientProvider } from '@tanstack/react-query';
import { renderHook } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { keysRunning, url } from '@/test/fixtures';
import { makeQueryClient } from '@/lib/queryClient';
import { useStartRewrap } from './keys';

it('start rewrap seeds status', async () => {
  server.use(http.post(url('/keys/rewrap'), () => HttpResponse.json(keysRunning, { status: 202 })));
  const qc = makeQueryClient({ test: true });
  const { result } = renderHook(() => useStartRewrap(), {
    wrapper: ({ children }) => createElement(QueryClientProvider, { client: qc }, children),
  });
  await result.current.mutateAsync();
  expect(qc.getQueryData(['keys-status'])).toEqual(keysRunning);
});
