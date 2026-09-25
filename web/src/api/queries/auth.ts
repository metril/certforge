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

export const authMethodsQuery = queryOptions({
  queryKey: ['auth-methods'],
  queryFn: () => call(api.GET('/auth/methods')),
  staleTime: 60_000,
  retry: false,
});

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    // Login answers with Me (1A), so the session's CSRF token is known at once.
    mutationFn: (password: string) => call(api.POST('/auth/login', { body: { password } })),
    meta: { silent: true },
    // Fix round 1: don't let a submitted password linger in the mutation cache.
    gcTime: 0,
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

export type SetupInput = { adminPassword: string; orgName: string; orgSlug: string; baseUrl: string };

export function useCompleteSetup() {
  const qc = useQueryClient();
  return useMutation({
    // Setup signs the admin in and answers with Me (1A); no second login call.
    mutationFn: (input: SetupInput) => call(api.POST('/setup/complete', { body: input })),
    // Fix round 1: SetupWizard handles its own error display (409 recovery vs.
    // inline detail), so the global mutation-cache toast would double up.
    meta: { silent: true },
    // Fix round 1: don't let the submitted admin password linger in the cache.
    gcTime: 0,
    onSuccess: (me) => {
      resetUnauthorized();
      setCsrfToken(me.csrfToken);
      qc.setQueryData(meQuery.queryKey, me);
      qc.setQueryData(setupStatusQuery.queryKey, { needsSetup: false });
    },
  });
}
