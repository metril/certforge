import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { TAB_ACTIVE, TAB_LINK, TabLabel } from '@/components/TabLabel';
import { useOrg } from '@/lib/org';

// Task 2: private CAs are no longer a separate, disabled tab — the CAs tab
// itself now covers every kind (Type chip, filter, kind-aware CaSheet).
export function IssuersLayout({ children }: { children: ReactNode }) {
  const { slug: org } = useOrg();
  return (
    <>
      <PageHeader title="Issuers" />
      <nav aria-label="Issuers" className="mb-6 flex gap-6 overflow-x-auto border-b border-border">
        <Link to="/o/$org/issuers/cas" params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE}>
          CAs
        </Link>
        <Link to="/o/$org/issuers/accounts" params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE} aria-label="ACME accounts">
          <TabLabel full="ACME accounts" short="Accounts" />
        </Link>
        <Link to="/o/$org/issuers/dns" params={{ org }} className={TAB_LINK} activeProps={TAB_ACTIVE} aria-label="DNS credentials">
          <TabLabel full="DNS credentials" short="DNS" />
        </Link>
      </nav>
      {children}
    </>
  );
}
