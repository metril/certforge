import { createFileRoute, Outlet } from '@tanstack/react-router';
import { IssuersLayout } from '@/features/issuers/IssuersLayout';

export const Route = createFileRoute('/_app/o/$org/issuers')({
  component: () => (
    <IssuersLayout>
      <Outlet />
    </IssuersLayout>
  ),
});
