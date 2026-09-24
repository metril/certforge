import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/o/$org/certificates/$id/')({
  beforeLoad: ({ params }) => {
    throw redirect({ to: '/o/$org/certificates/$id/$tab', params: { ...params, tab: 'overview' } });
  },
});
