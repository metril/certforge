import type { ReactNode } from 'react';
import { Link, useLocation } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { TAB_ACTIVE, TAB_LINK, TabLabel } from '@/components/TabLabel';
import { useOrg } from '@/lib/org';

// design.md navigation: Delivery = Deploy targets, File layouts, Actions, Credentials.
const DELIVERY_TABS = [
  { to: '/o/$org/delivery/targets', full: 'Deploy targets', short: 'Targets' },
  { to: '/o/$org/delivery/layouts', full: 'File layouts', short: 'Layouts' },
  { to: '/o/$org/delivery/actions', full: 'Actions', short: 'Actions' },
  { to: '/o/$org/delivery/credentials', full: 'Credentials', short: 'Creds' },
] as const;

export function DeliveryLayout({ children }: { children: ReactNode }) {
  const { slug: org } = useOrg();
  // Target create / edit / detail pages bring their own header and breadcrumb.
  const own = /\/delivery\/targets\/[^/]+/.test(useLocation().pathname);
  if (own) return <>{children}</>;
  return (
    <>
      <PageHeader
        title="Delivery"
        help="target.runsOn"
        tabsLabel="Delivery"
        tabs={DELIVERY_TABS.map((t) => (
          <Link key={t.to} to={t.to} params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE} aria-label={t.full}>
            <TabLabel full={t.full} short={t.short} />
          </Link>
        ))}
      />
      {children}
    </>
  );
}
