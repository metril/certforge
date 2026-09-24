import type { ReactNode } from 'react';
import { Link, useLocation } from '@tanstack/react-router';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { LATER, NAV, navPrefix, type NavItem, type NavTarget } from '@/lib/nav';
import { useActiveOrgSlug } from '@/lib/org';
import { cn } from '@/lib/utils';
import { OrgSwitcher } from './OrgSwitcher';
import { UserMenu } from './UserMenu';
import { Wordmark } from './Wordmark';

const rowClass =
  'flex h-9 items-center gap-3 border-l-2 border-transparent px-4 text-sm text-ink-muted hover:bg-subtle hover:text-ink';
const activeClass = 'border-primary bg-panel font-semibold text-ink';

function TargetLink({
  target,
  org,
  className,
  label,
  active,
  onNavigate,
  children,
}: {
  target: NavTarget;
  org: string;
  className: string;
  label?: string;
  active: boolean;
  onNavigate?: () => void;
  children: ReactNode;
}) {
  const common = { className, 'aria-label': label, 'aria-current': active ? ('page' as const) : undefined, onClick: onNavigate };
  switch (target) {
    case 'overview':
      return (
        <Link to="/o/$org/overview" params={{ org }} {...common}>
          {children}
        </Link>
      );
    case 'certificates':
      return (
        <Link to="/o/$org/certificates" params={{ org }} {...common}>
          {children}
        </Link>
      );
    case 'issuers':
      return (
        <Link to="/o/$org/issuers" params={{ org }} {...common}>
          {children}
        </Link>
      );
    case 'settings':
      return (
        <Link to="/settings/$section" params={{ section: 'general' }} {...common}>
          {children}
        </Link>
      );
  }
}

function NavRow({
  item,
  org,
  pathname,
  compact,
  onNavigate,
}: {
  item: NavItem;
  org: string;
  pathname: string;
  compact: boolean;
  onNavigate?: () => void;
}) {
  const Icon = item.icon;
  const body = (
    <>
      <Icon className="size-4 shrink-0" aria-hidden />
      {!compact && <span className="truncate">{item.label}</span>}
    </>
  );
  const cls = cn(rowClass, compact && 'justify-center px-0');
  if (!item.target) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            role="link"
            aria-disabled="true"
            tabIndex={0}
            aria-label={compact ? item.label : undefined}
            className={cn(cls, 'cursor-not-allowed opacity-50 hover:bg-transparent hover:text-ink-muted')}
          >
            {body}
          </span>
        </TooltipTrigger>
        <TooltipContent side="right">{LATER}</TooltipContent>
      </Tooltip>
    );
  }
  const active = pathname.startsWith(navPrefix(item.target, org));
  const link = (
    <TargetLink
      target={item.target}
      org={org}
      active={active}
      label={compact ? item.label : undefined}
      onNavigate={onNavigate}
      className={cn(cls, active && activeClass)}
    >
      {body}
    </TargetLink>
  );
  if (!compact) return link;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{item.label}</TooltipContent>
    </Tooltip>
  );
}

export function Sidebar({ compact, onNavigate }: { compact: boolean; onNavigate?: () => void }) {
  const org = useActiveOrgSlug() ?? '';
  const pathname = useLocation({ select: (l) => l.pathname });
  return (
    <nav aria-label="Main" className="flex h-full flex-col gap-5 py-4">
      <div className="grid gap-2">
        <div className={cn('px-4', compact && 'flex justify-center px-0')}>
          <Wordmark compact={compact} />
        </div>
        <OrgSwitcher activeOrg={org} compact={compact} />
      </div>
      <div className="grid flex-1 content-start gap-4 overflow-y-auto">
        {NAV.map((g) => (
          <div key={g.group} className="grid gap-0.5">
            {!compact && <p className="px-4 pb-1 text-xs text-ink-muted">{g.group}</p>}
            {g.items.map((item) => (
              <NavRow key={item.label} item={item} org={org} pathname={pathname} compact={compact} onNavigate={onNavigate} />
            ))}
          </div>
        ))}
      </div>
      <UserMenu compact={compact} />
    </nav>
  );
}
