import { createFileRoute, Outlet } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';

export const Route = createFileRoute('/_app/o/$org/issuers')({
  component: () => (
    <>
      <PageHeader title="Issuers" />
      <Outlet />
    </>
  ),
});
