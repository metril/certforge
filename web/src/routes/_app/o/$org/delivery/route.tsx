import { createFileRoute, Outlet } from '@tanstack/react-router';
import { DeliveryLayout } from '@/features/delivery/DeliveryLayout';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/delivery')({
  beforeLoad: ({ context }) => denyAllOrgs(context),
  component: () => (
    <DeliveryLayout>
      <Outlet />
    </DeliveryLayout>
  ),
});
