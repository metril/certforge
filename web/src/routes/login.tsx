import { createFileRoute, redirect } from '@tanstack/react-router';
import { z } from 'zod';
import { ApiError } from '@/api/errors';
import { meQuery, setupStatusQuery } from '@/api/queries/auth';
import { LoginPage } from '@/features/auth/LoginPage';
import { safeRedirect } from '@/features/auth/redirect';

export const Route = createFileRoute('/login')({
  // Adaptation (fix round 1, controller ruling): the return-URL search
  // param is `next` (matching client.ts's defaultUnauthorized, the
  // reference emitter), not `redirect`.
  validateSearch: z.object({ next: z.string().optional().catch(undefined) }),
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
      if (e instanceof ApiError && e.status === 401) return;
      throw e;
    }
    throw redirect({ href: safeRedirect(search.next) });
  },
  component: function LoginRoute() {
    const { next: target } = Route.useSearch();
    return <LoginPage redirectTo={safeRedirect(target)} />;
  },
});
