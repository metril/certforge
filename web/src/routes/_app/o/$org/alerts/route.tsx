import { createFileRoute, Outlet } from '@tanstack/react-router';
import { AlertsLayout } from '@/features/alerts/AlertsLayout';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/alerts')({
  beforeLoad: ({ context }) => denyAllOrgs(context),
  component: () => (
    <AlertsLayout>
      <Outlet />
    </AlertsLayout>
  ),
});
