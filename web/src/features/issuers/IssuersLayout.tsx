import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { LATER } from '@/lib/nav';
import { useOrg } from '@/lib/org';

const tab = 'inline-flex h-9 items-center border-b-2 border-transparent px-1 text-sm text-ink-muted hover:text-ink';
const activeTab = { className: 'border-primary! font-semibold text-ink!', 'aria-current': 'page' as const };

export function IssuersLayout({ children }: { children: ReactNode }) {
  const { slug: org } = useOrg();
  return (
    <>
      <PageHeader title="Issuers" />
      <nav aria-label="Issuers" className="mb-6 flex gap-6 border-b border-border">
        <Link to="/o/$org/issuers/cas" params={{ org }} className={tab} activeProps={activeTab}>
          CAs
        </Link>
        <Link to="/o/$org/issuers/accounts" params={{ org }} className={tab} activeProps={activeTab}>
          ACME accounts
        </Link>
        <Link to="/o/$org/issuers/dns" params={{ org }} className={tab} activeProps={activeTab}>
          DNS credentials
        </Link>
        <Tooltip>
          <TooltipTrigger asChild>
            <span role="link" aria-disabled="true" tabIndex={0} className={`${tab} cursor-not-allowed opacity-50`}>
              Private CAs
            </span>
          </TooltipTrigger>
          <TooltipContent>{LATER}</TooltipContent>
        </Tooltip>
      </nav>
      {children}
    </>
  );
}
