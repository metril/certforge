import { createFileRoute, redirect } from '@tanstack/react-router';
import { DEFAULT_CLIENT_TAB } from '@/features/clients/detail/tabs';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/clients/$id/')({
  beforeLoad: ({ context, params }) => {
    denyAllOrgs(context);
    throw redirect({ to: '/o/$org/clients/$id/$tab', params: { ...params, tab: DEFAULT_CLIENT_TAB } });
  },
});
