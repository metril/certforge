import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { TAB_ACTIVE, TAB_LINK, TabLabel } from '@/components/TabLabel';
import { useOrg } from '@/lib/org';

// design.md navigation: Delivery = Deploy targets, File layouts, Hooks.
const DELIVERY_TABS = [
  { to: '/o/$org/delivery/targets', full: 'Deploy targets', short: 'Targets' },
  { to: '/o/$org/delivery/layouts', full: 'File layouts', short: 'Layouts' },
] as const;

export function DeliveryLayout({ children }: { children: ReactNode }) {
  const { slug: org } = useOrg();
  return (
    <>
      <PageHeader title="Delivery" />
      <nav aria-label="Delivery" className="mb-6 flex gap-6 overflow-x-auto border-b border-border">
        {DELIVERY_TABS.map((t) => (
          <Link key={t.to} to={t.to} params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE} aria-label={t.full}>
            <TabLabel full={t.full} short={t.short} />
          </Link>
        ))}
      </nav>
      {children}
    </>
  );
}
