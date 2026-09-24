import type { QueryClient } from '@tanstack/react-query';
import { createRootRouteWithContext, Link, Outlet } from '@tanstack/react-router';

export type RouterContext = { queryClient: QueryClient };

export const Route = createRootRouteWithContext<RouterContext>()({
  component: Outlet,
  notFoundComponent: () => (
    <main className="grid gap-3 p-8">
      <h1 className="text-xl font-semibold">Page not found</h1>
      <Link to="/" className="text-primary underline underline-offset-2">
        Go to overview
      </Link>
    </main>
  ),
});
