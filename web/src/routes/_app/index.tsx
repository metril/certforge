import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/')({
  beforeLoad: ({ context: { me } }) => {
    const first = me.orgs[0];
    if (!first) throw new Error('No organization exists yet. Finish first-run setup.');
    throw redirect({ to: '/o/$org/overview', params: { org: first.slug } });
  },
});
