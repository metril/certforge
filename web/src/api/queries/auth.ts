import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call, resetUnauthorized, setCsrfToken } from '../client';

export const meQuery = queryOptions({
  queryKey: ['me'],
  queryFn: async () => {
    const me = await call(api.GET('/auth/me'));
    setCsrfToken(me.csrfToken);
    return me;
  },
  staleTime: 60_000,
  retry: false,
});

export const setupStatusQuery = queryOptions({
  queryKey: ['setup-status'],
  queryFn: () => call(api.GET('/setup/status')),
  staleTime: Infinity,
  retry: false,
});

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    // Login answers with Me (1A), so the session's CSRF token is known at once.
    mutationFn: (password: string) => call(api.POST('/auth/login', { body: { password } })),
    meta: { silent: true },
    onSuccess: (me) => {
      resetUnauthorized();
      setCsrfToken(me.csrfToken);
      qc.setQueryData(meQuery.queryKey, me);
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => call(api.POST('/auth/logout')),
    onSettled: () => {
      setCsrfToken(null);
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'setup-status' });
    },
  });
}
