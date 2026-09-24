import { createFileRoute, notFound } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/o/$org')({
  beforeLoad: ({ context: { me }, params }) => {
    const org = me.orgs.find((o) => o.slug === params.org);
    if (!org) throw notFound();
    return { org };
  },
});
