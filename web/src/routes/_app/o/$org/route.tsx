import { createFileRoute, notFound } from '@tanstack/react-router';
import { ALL_ORGS, ALL_ORGS_SLUG } from '@/lib/org';
import { hasGlobalBinding } from '@/lib/permissions';

export const Route = createFileRoute('/_app/o/$org')({
  beforeLoad: ({ context: { me }, params }) => {
    if (params.org === ALL_ORGS_SLUG) {
      if (!hasGlobalBinding(me)) throw notFound();
      return { org: ALL_ORGS, allOrgs: true };
    }
    const org = me.orgs.find((o) => o.slug === params.org);
    if (!org) throw notFound();
    return { org, allOrgs: false };
  },
});
