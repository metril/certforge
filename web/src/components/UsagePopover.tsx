import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, type LinkProps } from '@tanstack/react-router';
import { errorMessage } from '@/api/errors';
import { entityTarget, type EntityKind } from '@/components/EntityLink';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { useOrg } from '@/lib/org';

export type UsageItem = { id: string; name: string; kind: Exclude<EntityKind, 'grant'> };
export type Usage = { items: UsageItem[]; note?: string };

const rowCls = 'block truncate rounded-sm px-2 py-1.5 text-xs font-medium outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring';

/**
 * A label that opens a click popover listing what uses a record, each item
 * linking to it. Plain text when the viewer cannot read the list or it is empty.
 * The list loads when the popover first opens.
 */
export function UsagePopover({ label, count, allowed, queryKey, load }: { label: string; count: number; allowed: boolean; queryKey: readonly unknown[]; load: () => Promise<Usage> }) {
  const org = useOrg();
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ['usage', ...queryKey], queryFn: load, enabled: open && allowed });
  if (count === 0 || !allowed) return <span className="whitespace-nowrap">{label}</span>;
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button type="button" className="whitespace-nowrap rounded-sm text-left underline-offset-2 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring">
          {label}
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-72 p-1">
        <div className="max-h-72 overflow-y-auto">
          {q.isError ? (
            <p className="p-2 text-xs text-failed">Couldn&apos;t load the list. {errorMessage(q.error)}</p>
          ) : q.isPending ? (
            <p className="p-2 text-xs text-ink-muted">Loading…</p>
          ) : (
            <>
              {q.data.items.map((i) => (
                <Link key={i.id} {...(entityTarget(i.kind, i.id, org.slug) as LinkProps)} className={rowCls}>
                  {i.name}
                </Link>
              ))}
              {q.data.note && <p className="px-2 py-1.5 text-xs text-ink-muted">{q.data.note}</p>}
              {q.data.items.length === 0 && !q.data.note && <p className="p-2 text-xs text-ink-muted">Nothing uses it.</p>}
            </>
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}
