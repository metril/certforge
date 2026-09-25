import { Link } from '@tanstack/react-router';
import { Check, ChevronsUpDown } from 'lucide-react';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { hasGlobalBinding } from '@/lib/permissions';
import { ALL_ORGS, ALL_ORGS_SLUG, useMe } from '@/lib/org';
import { cn } from '@/lib/utils';

/**
 * Switches between orgs; admins with a global binding also get the
 * read-only All orgs view. Spec: "Org switcher at the top of the sidebar
 * (hidden in Phase 1 when there is a single org, but the component
 * exists)". Phase 1 fixtures and deployments have exactly one org, so this
 * renders nothing until a second org exists.
 */
export function OrgSwitcher({ activeOrg, compact }: { activeOrg?: string; compact: boolean }) {
  const me = useMe();
  const globalBinding = hasGlobalBinding(me);
  if (me.orgs.length <= 1 && !globalBinding) return null;
  const current = activeOrg === ALL_ORGS_SLUG ? ALL_ORGS : (me.orgs.find((o) => o.slug === activeOrg) ?? me.orgs[0]);
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          // Fix round 1 (review, WCAG label-in-name): the visible label
          // (below, when not compact) is the org name, so the accessible
          // name must contain it verbatim, not just "Switch organization".
          aria-label={`Organization: ${current?.name ?? ''}`}
          className={cn(
            'mx-2 flex h-8 items-center gap-2 rounded-md px-2 text-sm text-ink hover:bg-subtle',
            compact && 'justify-center px-0',
          )}
        >
          {!compact && <span className="truncate">{current?.name}</span>}
          <ChevronsUpDown className="size-3.5 shrink-0 text-ink-muted" aria-hidden />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-56">
        {globalBinding && (
          <>
            <DropdownMenuItem asChild>
              <Link to="/o/$org/overview" params={{ org: ALL_ORGS_SLUG }} className="flex items-center justify-between gap-2">
                All orgs
                {current?.slug === ALL_ORGS_SLUG && <Check className="size-4" aria-hidden />}
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
          </>
        )}
        {me.orgs.map((o) => (
          <DropdownMenuItem key={o.id} asChild>
            <Link to="/o/$org/overview" params={{ org: o.slug }} className="flex items-center justify-between gap-2">
              {o.name}
              {o.slug === current?.slug && <Check className="size-4" aria-hidden />}
            </Link>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
