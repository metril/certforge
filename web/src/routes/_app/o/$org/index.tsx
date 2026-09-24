import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/o/$org/')({
  beforeLoad: ({ params }) => {
    throw redirect({ to: '/o/$org/overview', params });
  },
});
