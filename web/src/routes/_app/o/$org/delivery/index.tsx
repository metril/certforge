import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/o/$org/delivery/')({
  beforeLoad: ({ params }) => {
    throw redirect({ to: '/o/$org/delivery/targets', params });
  },
});
