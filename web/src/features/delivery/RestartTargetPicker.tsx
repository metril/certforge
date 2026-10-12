import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { allClientsQuery } from '@/api/queries/clients';
import type { Client } from '@/api/types';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

export const NOT_ALLOWED_TIP = "Not in this agent's CF_RESTART_ALLOW";

const byRestart = (a: Client, b: Client) => Number(b.capabilities.includes('restart')) - Number(a.capabilities.includes('restart')) || a.name.localeCompare(b.name);

/** Lists what a client's agent reported it can restart. Allowed targets fill the
 * field; the rest are shown greyed. Browsing never widens CF_RESTART_ALLOW. */
export function RestartTargetPicker({ orgId, onPick }: { orgId: string; onPick: (target: string) => void }) {
  const q = useQuery(allClientsQuery(orgId));
  const clients = useMemo(() => [...(q.data?.items ?? [])].filter((c) => c.status === 'active').sort(byRestart), [q.data]);
  const [clientId, setClientId] = useState<string>('');
  const client = clients.find((c) => c.id === (clientId || clients[0]?.id));
  if (q.isPending) return <p className="text-sm text-ink-muted">Loading clients…</p>;
  if (q.isError) return <p className="text-sm text-ink-muted">Clients could not be loaded.</p>;
  if (clients.length === 0) return <p className="text-sm text-ink-muted">No active clients in this org.</p>;
  const targets = client?.restartTargets ?? [];
  return (
    <div className="grid gap-2 rounded-md border border-border p-3">
      <label className="grid gap-1 text-sm font-medium">
        Client
        <select
          aria-label="Client"
          className="h-9 rounded-md border border-border bg-transparent px-2 text-sm font-normal"
          value={client?.id ?? ''}
          onChange={(e) => setClientId(e.target.value)}
        >
          {clients.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
              {c.capabilities.includes('restart') ? '' : ' (no restart capability)'}
            </option>
          ))}
        </select>
      </label>
      {targets.length === 0 ? (
        <p className="text-sm text-ink-muted">This agent has not reported any restart targets. Set CF_RESTART_ALLOW on it.</p>
      ) : (
        <ul aria-label="Restart targets" className="grid max-h-56 gap-1 overflow-y-auto">
          {targets.map((t) => (
            <li key={t.target}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    aria-disabled={!t.allowed}
                    onClick={() => t.allowed && onPick(t.target)}
                    className={cn(
                      'flex min-h-8 w-full items-center gap-2 rounded-md border border-border px-2 text-left font-mono text-sm',
                      t.allowed ? 'hover:bg-muted' : 'cursor-not-allowed text-ink-muted opacity-60',
                    )}
                  >
                    <span className="min-w-0 flex-1 truncate">{t.target}</span>
                    {t.running != null && <span className="font-sans text-xs text-ink-muted">{t.running ? 'running' : 'stopped'}</span>}
                  </button>
                </TooltipTrigger>
                {!t.allowed && <TooltipContent>{NOT_ALLOWED_TIP}</TooltipContent>}
              </Tooltip>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
