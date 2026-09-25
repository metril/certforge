import { createFileRoute, Outlet } from '@tanstack/react-router';
import { IssuersLayout } from '@/features/issuers/IssuersLayout';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/issuers')({
  beforeLoad: ({ context }) => denyAllOrgs(context),
  component: () => (
    <IssuersLayout>
      <Outlet />
    </IssuersLayout>
  ),
});
