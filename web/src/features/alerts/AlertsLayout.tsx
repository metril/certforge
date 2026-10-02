import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHeader, type PageHeaderProps } from '@/components/PageHeader';
import { TAB_ACTIVE, TAB_LINK } from '@/components/TabLabel';
import { useOrg } from '@/lib/org';

const ALERTS_TABS = [
  { to: '/o/$org/alerts/channels', label: 'Channels' },
  { to: '/o/$org/alerts/monitors', label: 'Monitors' },
  { to: '/o/$org/alerts/events', label: 'Events' },
] as const;

/** Alerts title, tabs, and (per page) one help tip, filters and actions.
 * Each tab page renders its own, so its filters sit in the toolbar under the tabs. */
export function AlertsHeader(props: Pick<PageHeaderProps, 'help' | 'filters' | 'activeFilters' | 'actions' | 'onClearFilters' | 'filtersTrailing' | 'filterChips'>) {
  const { slug: org } = useOrg();
  return (
    <PageHeader
      title="Alerts"
      tabsLabel="Alerts"
      tabs={ALERTS_TABS.map((t) => (
        <Link key={t.to} to={t.to} params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE}>
          {t.label}
        </Link>
      ))}
      {...props}
    />
  );
}

export function AlertsLayout({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
