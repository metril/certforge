import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/o/$org/issuers/')({
  beforeLoad: ({ params }) => {
    throw redirect({ to: '/o/$org/issuers/cas', params });
  },
});
