import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/')({
  beforeLoad: ({ context: { me } }) => {
    const first = me.orgs[0];
    // Fix round 1 (review): a raw thrown Error surfaced as a crash instead
    // of a graceful page; route to the empty state instead.
    if (!first) throw redirect({ to: '/no-organization' });
    throw redirect({ to: '/o/$org/overview', params: { org: first.slug } });
  },
});
