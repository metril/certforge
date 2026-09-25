import { createFileRoute, redirect } from '@tanstack/react-router';
import { z } from 'zod';
import { ApiError } from '@/api/errors';
import { authMethodsQuery, meQuery, setupStatusQuery } from '@/api/queries/auth';
import { LoginPage } from '@/features/auth/LoginPage';
import { safeRedirect } from '@/features/auth/redirect';

export const Route = createFileRoute('/login')({
  // Adaptation (fix round 1, controller ruling): the return-URL search
  // param is `next` (matching client.ts's defaultUnauthorized, the
  // reference emitter), not `redirect`.
  // Adaptation: no `.max(64)` on `error` — an overlong or unrecognised
  // code must still reach oidcErrorMessage() so it falls back to the
  // generic "Single sign-on failed. Try again." line; discarding it here
  // (`.catch(undefined)`) would render no message at all instead.
  validateSearch: z.object({
    next: z.string().optional().catch(undefined),
    error: z.string().optional().catch(undefined),
  }),
  beforeLoad: async ({ context, search }) => {
    const status = await context.queryClient.ensureQueryData(setupStatusQuery);
    if (status.needsSetup) throw redirect({ to: '/setup' });
    // Adaptation (controller ruling; preflight A28): a valid session cookie
    // still 403s the next mutating call without a fresh CSRF token, even on
    // a public route. Probing /auth/me here both sends an already-signed-in
    // visitor straight to their target and caches Me's csrfToken before the
    // sign-in form's own POST.
    try {
      await context.queryClient.ensureQueryData(meQuery);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        // Prefetch so LoginPage's own useQuery(authMethodsQuery) already
        // has data by first render, avoiding a layout flash between the
        // password form and the single sign-on button. Never throws: a
        // failed /auth/methods fetch just leaves the page to fall back to
        // the password form via its own query state.
        await context.queryClient.prefetchQuery(authMethodsQuery);
        return;
      }
      throw e;
    }
    throw redirect({ href: safeRedirect(search.next) });
  },
  component: function LoginRoute() {
    const { next: target, error } = Route.useSearch();
    return <LoginPage redirectTo={safeRedirect(target)} error={error} />;
  },
});
