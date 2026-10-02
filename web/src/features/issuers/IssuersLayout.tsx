import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHeader, type PageHeaderProps } from '@/components/PageHeader';
import { TAB_ACTIVE, TAB_LINK, TabLabel } from '@/components/TabLabel';
import { useOrg } from '@/lib/org';

/** Issuers title, tabs, and (per page) one help tip, filters and actions.
 * Each tab page renders its own, so its filters can share the tab line. The
 * CAs tab covers every kind (Type filter, kind-aware CaSheet). */
export function IssuersHeader(props: Pick<PageHeaderProps, 'help' | 'filters' | 'activeFilters' | 'actions'>) {
  const { slug: org } = useOrg();
  return (
    <PageHeader
      title="Issuers"
      tabsLabel="Issuers"
      tabs={
        <>
          <Link to="/o/$org/issuers/cas" params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE}>
            CAs
          </Link>
          <Link to="/o/$org/issuers/accounts" params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE} aria-label="ACME accounts">
            <TabLabel full="ACME accounts" short="Accounts" />
          </Link>
          <Link to="/o/$org/issuers/dns" params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE} aria-label="DNS credentials">
            <TabLabel full="DNS credentials" short="DNS" />
          </Link>
        </>
      }
      {...props}
    />
  );
}

export function IssuersLayout({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
