import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/o/$org/alerts/')({
  beforeLoad: ({ params }) => {
    throw redirect({ to: '/o/$org/alerts/channels', params });
  },
});
