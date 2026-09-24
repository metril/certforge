import { createFileRoute, Outlet, redirect } from '@tanstack/react-router';
import { ApiError } from '@/api/errors';
import { meQuery, setupStatusQuery } from '@/api/queries/auth';

export const Route = createFileRoute('/_app')({
  beforeLoad: async ({ context: { queryClient }, location }) => {
    const status = await queryClient.ensureQueryData(setupStatusQuery);
    if (status.needsSetup) throw redirect({ to: '/setup' });
    try {
      const me = await queryClient.ensureQueryData(meQuery);
      return { me };
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) throw redirect({ to: '/login', search: { redirect: location.href } });
      throw e;
    }
  },
  component: Outlet,
});
