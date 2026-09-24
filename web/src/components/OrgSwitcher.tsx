import { Link } from '@tanstack/react-router';
import { Check, ChevronsUpDown } from 'lucide-react';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useMe } from '@/lib/org';
import { cn } from '@/lib/utils';

/**
 * Switches between orgs. Spec: "Org switcher at the top of the sidebar
 * (hidden in Phase 1 when there is a single org, but the component
 * exists)". Phase 1 fixtures and deployments have exactly one org, so this
 * renders nothing until a second org exists.
 */
export function OrgSwitcher({ activeOrg, compact }: { activeOrg?: string; compact: boolean }) {
  const me = useMe();
  if (me.orgs.length <= 1) return null;
  const current = me.orgs.find((o) => o.slug === activeOrg) ?? me.orgs[0];
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label="Switch organization"
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
