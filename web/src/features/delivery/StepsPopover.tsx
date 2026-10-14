import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { actionGroupsQuery, actionsQuery } from '@/api/queries/delivery';
import type { GrantStep } from '@/api/types';
import { EntityLink } from '@/components/EntityLink';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';

/** A grant's step count that opens a click popover listing the steps, each linking to its action or group. */
export function StepsPopover({ steps, label }: { steps: GrantStep[]; label?: string }) {
  const org = useOrg();
  const me = useMe();
  const [open, setOpen] = useState(false);
  const text = label ?? (steps.length || '–');
  const allowed = can(me, 'delivery:read', org.id);
  const actionsQ = useQuery({ ...actionsQuery(org.id), enabled: open && allowed });
  const groupsQ = useQuery({ ...actionGroupsQuery(org.id), enabled: open && allowed });
  if (steps.length === 0 || !allowed) return <>{text}</>;
  const nameOf = (s: GrantStep) =>
    'action' in s ? (actionsQ.data?.find((a) => a.id === s.action)?.name ?? 'Action') : (groupsQ.data?.find((g) => g.id === s.group)?.name ?? 'Group');
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button type="button" className="whitespace-nowrap rounded-sm text-left underline-offset-2 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring">
          {text}
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 p-1">
        <ol className="max-h-72 overflow-y-auto">
          {steps.map((s, i) => (
            <li key={i} className="flex items-baseline gap-2 rounded-sm px-2 py-1.5 text-xs">
              <span className="text-ink-muted tabular-nums">{i + 1}.</span>
              <EntityLink kind={'action' in s ? 'action' : 'actionGroup'} id={'action' in s ? s.action : s.group} className="min-w-0 truncate font-medium">
                {nameOf(s)}
              </EntityLink>
              {'group' in s && <span className="text-ink-muted">group</span>}
            </li>
          ))}
        </ol>
      </PopoverContent>
    </Popover>
  );
}
