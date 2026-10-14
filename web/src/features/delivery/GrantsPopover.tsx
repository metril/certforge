import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { errorMessage } from '@/api/errors';
import { plural } from '@/api/queries/certificates';
import { grantsListQuery, type GrantsFilter } from '@/api/queries/grants';
import type { Grant } from '@/api/types';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';

const rowCls = 'grid gap-0.5 rounded-sm px-2 py-1.5 text-xs outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring';

function GrantRow({ g, orgSlug }: { g: Grant; orgSlug: string }) {
  const where = g.runsOn === 'server' ? `server · ${g.deployTargetName ?? 'target'}` : `agent · ${g.clientName ?? 'client'}`;
  const body = (
    <>
      <span className="truncate font-medium">{g.certificateName}</span>
      <span className="truncate text-ink-muted">
        {where}
        {g.layoutName ? ` · ${g.layoutName}` : ''}
      </span>
    </>
  );
  // A server grant opens on its target's Grants tab, an agent grant on its client's Certificates tab.
  if (g.runsOn === 'server' && g.deployTargetId)
    return (
      <Link to="/o/$org/delivery/targets/$id/$tab" params={{ org: orgSlug, id: g.deployTargetId, tab: 'grants' }} search={{ open: g.id }} className={rowCls}>
        {body}
      </Link>
    );
  if (g.clientId)
    return (
      <Link to="/o/$org/clients/$id/$tab" params={{ org: orgSlug, id: g.clientId, tab: 'certificates' }} search={{ open: g.id }} className={rowCls}>
        {body}
      </Link>
    );
  return <div className={rowCls}>{body}</div>;
}

/** "N grants" that opens a click popover listing them, each linking to its grant. */
export function GrantsPopover({ count, filter }: { count: number; filter: GrantsFilter }) {
  const org = useOrg();
  const me = useMe();
  const [open, setOpen] = useState(false);
  const label = plural(count, 'grant');
  const allowed = can(me, 'clients:read', org.id);
  const q = useQuery({ ...grantsListQuery(org.id, filter), enabled: open && allowed });
  if (count === 0 || !allowed) return <span className="whitespace-nowrap">{label}</span>;
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button type="button" className="whitespace-nowrap rounded-sm text-left underline-offset-2 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring">
          {label}
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 p-1">
        <div className="max-h-72 overflow-y-auto">
          {q.isError ? (
            <p className="p-2 text-xs text-failed">Couldn&apos;t load grants. {errorMessage(q.error)}</p>
          ) : q.isPending ? (
            <p className="p-2 text-xs text-ink-muted">Loading…</p>
          ) : q.data.length === 0 ? (
            <p className="p-2 text-xs text-ink-muted">No grants.</p>
          ) : (
            q.data.map((g) => <GrantRow key={g.id} g={g} orgSlug={org.slug} />)
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}
