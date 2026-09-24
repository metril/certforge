import { createRootRoute, Outlet } from '@tanstack/react-router';

// Placeholder root route: Task 3 (router, login, setup wizard) replaces this
// with the real layout and auth guard. Needed now only so the TanStack
// Router Vite plugin (which scans src/routes at config-resolve time, even
// though main.tsx does not mount a router yet) does not fail the build.
export const Route = createRootRoute({
  component: Outlet,
});
