import type { QueryClient } from '@tanstack/react-query';
import { createRouter, type RouterHistory } from '@tanstack/react-router';
import { resetUnauthorized, setUnauthorizedHandler } from '@/api/client';
import { setupStatusQuery } from '@/api/queries/auth';
import { routeTree } from './routeTree.gen';

export function createAppRouter(queryClient: QueryClient, history?: RouterHistory) {
  const router = createRouter({
    routeTree,
    history,
    context: { queryClient },
    defaultPreload: 'intent',
    defaultPreloadStaleTime: 0,
    scrollRestoration: true,
  });
  resetUnauthorized();
  // Adaptation (controller ruling): replaces Task 2's default `window.location`
  // 401 handler with an SPA navigation that keeps the return URL, using the
  // same `next` search-param convention as client.ts's defaultUnauthorized
  // (fix round 1: it was `redirect` here, out of step with that convention).
  setUnauthorizedHandler(() => {
    const next = router.state.location.href;
    queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== setupStatusQuery.queryKey[0] });
    void router.navigate({ to: '/login', search: { next } });
  });
  return router;
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
