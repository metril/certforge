import { forwardRef, type ComponentPropsWithoutRef, type MouseEvent, type ReactNode } from 'react';
import { Link, useLocation } from '@tanstack/react-router';
import { Search } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import {
  ALL_ORGS_ONLY_ONE,
  ALL_ORGS_TARGETS,
  isNavPathActive,
  LATER,
  NAV,
  navPrefix,
  NO_AUDIT,
  NO_ORG,
  targetNeedsOrg,
  type NavItem,
  type NavTarget,
} from '@/lib/nav';
import { ALL_ORGS_SLUG, useActiveOrgSlug, useMe } from '@/lib/org';
import { canAnywhere } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { OrgSwitcher } from './OrgSwitcher';
import { UserMenu } from './UserMenu';
import { Wordmark } from './Wordmark';

const rowClass =
  'flex h-9 items-center gap-3 border-l-2 border-transparent px-4 text-sm text-ink-muted hover:bg-subtle hover:text-ink';
const activeClass = 'border-primary bg-panel font-semibold text-ink';

// C1 (Critical): NavRow passes this component's rendered element straight
// into `<TooltipTrigger asChild>`, which clones it and attaches a ref so
// Radix can anchor the icon-rail tooltip to the actual `<a>` DOM node.
// Without forwardRef, that ref dropped (React warned "Function components
// cannot be given refs") and the tooltip anchored nowhere, so it appeared at
// (0, -200%) instead of next to the link.
//
// Re-review fix: forwardRef alone wasn't enough — Radix's Slot also merges
// in its own onPointerMove/onFocus/onBlur (hover/focus-intent tracking)
// plus aria-describedby/data-state onto whatever element it clones, and
// this component was still destructuring only its own named props, so all
// of that landed in the void instead of on the rendered `<a>`. Without
// onPointerMove/onFocus/onBlur actually reaching the anchor, Radix never
// sees the hover/focus that should open the tooltip, so the compact
// icon-rail tooltips never opened even once forwardRef fixed their
// position. `...rest` now carries every such prop through; `onClick` is
// pulled out and composed with `onNavigate` instead of just overwritten,
// since a future Slot-provided onClick (there is none today, but Radix's
// merge convention always composes rather than assumes ownership) must
// still run.
const TargetLink = forwardRef<
  HTMLAnchorElement,
  {
    target: NavTarget;
    org: string;
    label?: string;
    active: boolean;
    onNavigate?: () => void;
    children: ReactNode;
  } & Omit<ComponentPropsWithoutRef<'a'>, 'target' | 'children'>
>(function TargetLink({ target, org, label, active, onNavigate, onClick, children, ...rest }, ref) {
  // The single source of truth for "is this item active" is `active`
  // (nav.ts's isNavPathActive, a segment-boundary-aware prefix match run
  // against the current pathname), not TanStack Router's own built-in
  // Link active-state: that compares against this Link's own literal
  // resolved href, which can't know that e.g. every /settings/:section
  // should light up the same "Settings" item.
  const common = {
    ref,
    ...rest,
    'aria-label': label,
    'aria-current': active ? ('page' as const) : undefined,
    onClick: (e: MouseEvent<HTMLAnchorElement>) => {
      onClick?.(e);
      onNavigate?.();
    },
  };
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
    case 'clients':
      return (
        <Link to="/o/$org/clients" params={{ org }} {...common}>
          {children}
        </Link>
      );
    case 'issuers':
      return (
        <Link to="/o/$org/issuers" params={{ org }} {...common}>
          {children}
        </Link>
      );
    case 'audit':
      return (
        <Link to="/o/$org/audit" params={{ org }} {...common}>
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
});
TargetLink.displayName = 'TargetLink';

function DisabledRow({ item, compact, reason }: { item: NavItem; compact: boolean; reason: string }) {
  const Icon = item.icon;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          role="link"
          aria-disabled="true"
          tabIndex={0}
          aria-label={compact ? item.label : undefined}
          className={cn(
            rowClass,
            compact && 'justify-center px-0',
            'cursor-not-allowed opacity-50 hover:bg-transparent hover:text-ink-muted',
          )}
        >
          <Icon className="size-4 shrink-0" aria-hidden />
          {!compact && <span className="truncate">{item.label}</span>}
        </span>
      </TooltipTrigger>
      <TooltipContent side="right">{reason}</TooltipContent>
    </Tooltip>
  );
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
  const me = useMe();
  if (!item.target) return <DisabledRow item={item} compact={compact} reason={LATER} />;
  if (targetNeedsOrg(item.target) && !org) return <DisabledRow item={item} compact={compact} reason={NO_ORG} />;
  if (item.target && org === ALL_ORGS_SLUG && !ALL_ORGS_TARGETS.has(item.target)) {
    return <DisabledRow item={item} compact={compact} reason={ALL_ORGS_ONLY_ONE} />;
  }
  if (item.target === 'audit' && !canAnywhere(me, 'audit:read')) return <DisabledRow item={item} compact={compact} reason={NO_AUDIT} />;

  const Icon = item.icon;
  const body = (
    <>
      <Icon className="size-4 shrink-0" aria-hidden />
      {!compact && <span className="truncate">{item.label}</span>}
    </>
  );
  const cls = cn(rowClass, compact && 'justify-center px-0');
  const active = isNavPathActive(pathname, navPrefix(item.target, org));
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

export function Sidebar({ compact, onNavigate, onSearch }: { compact: boolean; onNavigate?: () => void; onSearch?: () => void }) {
  const org = useActiveOrgSlug() ?? '';
  const pathname = useLocation({ select: (l) => l.pathname });
  return (
    <nav aria-label="Main" className="flex h-full flex-col gap-5 py-4">
      <div className="grid gap-2">
        <div className={cn('px-4', compact && 'flex justify-center px-0')}>
          <Wordmark compact={compact} />
        </div>
        <OrgSwitcher activeOrg={org} compact={compact} />
        {onSearch && (
          <div className={cn('px-3', compact && 'flex justify-center px-0')}>
            <button
              type="button"
              onClick={onSearch}
              aria-label="Search (Ctrl K)"
              className={cn(
                'flex h-8 w-full items-center gap-2 rounded-md border border-border bg-panel px-2 text-sm text-ink-muted hover:text-ink',
                compact && 'w-9 justify-center px-0',
              )}
            >
              <Search className="size-4" aria-hidden />
              {!compact && (
                <>
                  <span>Search</span>
                  <kbd className="ml-auto font-sans text-xs">Ctrl K</kbd>
                </>
              )}
            </button>
          </div>
        )}
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
