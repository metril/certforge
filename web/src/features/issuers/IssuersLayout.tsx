import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { LATER } from '@/lib/nav';
import { useOrg } from '@/lib/org';

const tab = 'inline-flex h-9 shrink-0 items-center whitespace-nowrap border-b-2 border-transparent px-1 text-sm text-ink-muted hover:text-ink';
const activeTab = { className: 'border-primary! font-semibold text-ink!', 'aria-current': 'page' as const };

// Fix round 1 (#3): "ACME accounts" and "DNS credentials" wrap inside a 36px
// tab at narrow widths; a short label takes over below `md` (`CAs` and
// `Private CAs` are already short enough at every width). The two spans are
// `aria-hidden` and the link itself carries the full text as `aria-label`,
// so the accessible name is always the one, full label — independent of
// which span CSS happens to be showing (or, in a test environment with CSS
// disabled, showing both).
function TabLabel({ full, short }: { full: string; short: string }) {
  return (
    <>
      <span aria-hidden="true" className="hidden md:inline">
        {full}
      </span>
      <span aria-hidden="true" className="md:hidden">
        {short}
      </span>
    </>
  );
}

export function IssuersLayout({ children }: { children: ReactNode }) {
  const { slug: org } = useOrg();
  return (
    <>
      <PageHeader title="Issuers" />
      <nav aria-label="Issuers" className="mb-6 flex gap-6 overflow-x-auto border-b border-border">
        <Link to="/o/$org/issuers/cas" params={{ org }} className={tab} activeProps={activeTab}>
          CAs
        </Link>
        <Link to="/o/$org/issuers/accounts" params={{ org }} className={tab} activeProps={activeTab} aria-label="ACME accounts">
          <TabLabel full="ACME accounts" short="Accounts" />
        </Link>
        <Link to="/o/$org/issuers/dns" params={{ org }} className={tab} activeProps={activeTab} aria-label="DNS credentials">
          <TabLabel full="DNS credentials" short="DNS" />
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
