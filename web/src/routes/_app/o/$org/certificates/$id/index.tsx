import { createFileRoute, redirect } from '@tanstack/react-router';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/certificates/$id/')({
  beforeLoad: ({ context, params }) => {
    denyAllOrgs(context);
    throw redirect({ to: '/o/$org/certificates/$id/$tab', params: { ...params, tab: 'overview' } });
  },
});
