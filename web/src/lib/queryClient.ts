import { MutationCache, QueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';

declare module '@tanstack/react-query' {
  interface Register {
    mutationMeta: { silent?: boolean; success?: string };
  }
}

export function makeQueryClient(opts: { test?: boolean } = {}): QueryClient {
  return new QueryClient({
    mutationCache: new MutationCache({
      onError: (error, _vars, _ctx, mutation) => {
        if (!mutation.meta?.silent) toast.error(errorMessage(error));
      },
      onSuccess: (_data, _vars, _ctx, mutation) => {
        if (mutation.meta?.success) toast.success(mutation.meta.success);
      },
    }),
    defaultOptions: {
      queries: {
        staleTime: opts.test ? 0 : 10_000,
        gcTime: opts.test ? Infinity : 300_000,
        retry: opts.test ? false : (count, error) => !(error instanceof ApiError && error.status < 500) && count < 2,
        refetchOnWindowFocus: true,
      },
      mutations: { retry: false },
    },
  });
}
