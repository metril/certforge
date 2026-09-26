import { useEffect, useReducer } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { CircleX, LoaderCircle } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { clientQuery } from '@/api/queries/clients';
import type { Client } from '@/api/types';
import { ConnectionDot } from '@/components/ConnectionDot';
import { HelpTip } from '@/components/HelpTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { livePoll } from '@/lib/polling';
import { cn } from '@/lib/utils';

type Props = { orgId: string; orgSlug: string; clientId: string; expiresAt: string; renewing: boolean; onNewToken: () => void };

function isExpired(c: Pick<Client, 'status' | 'online'> | undefined, expiresAt: string): boolean {
  const online = c?.status === 'active' && c.online;
  return !online && c?.status === 'pending' && Date.parse(expiresAt) <= Date.now();
}

/** Live "waiting for agent": polls every 2 s until the client is active and
 * online (connected, or pulled recently), then offers the next step. */
export function WaitingPanel({ orgId, orgSlug, clientId, expiresAt, renewing, onNewToken }: Props) {
  const q = useQuery({
    ...clientQuery(orgId, clientId),
    refetchInterval: (query) => {
      const c = query.state.data;
      // Expiry is evaluated fresh (Date.now()) on every poll, so it stops
      // as soon as the token passes, without waiting on a separate ticker.
      if (isExpired(c, expiresAt)) return false;
      return livePoll(!(c?.status === 'active' && c.online));
    },
  });
  // Nothing about the query changes at the exact moment the token expires,
  // so a single timeout forces one more render then, to flip the border
  // and stop the "Waiting for agent" spinner without a repeating ticker.
  const [, forceUpdate] = useReducer((n: number) => n + 1, 0);
  useEffect(() => {
    const ms = Date.parse(expiresAt) - Date.now();
    if (ms <= 0) return;
    const t = window.setTimeout(forceUpdate, ms);
    return () => window.clearTimeout(t);
  }, [expiresAt]);
  const c = q.data;
  const online = c?.status === 'active' && c.online;
  const expired = isExpired(c, expiresAt);

  return (
    <section
      aria-label="Agent connection"
      aria-live="polite"
      className={cn('grid gap-3 rounded-md border p-4', online ? 'border-valid' : expired ? 'border-failed' : 'border-dashed border-pending')}
    >
      {online ? (
        <>
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
            <ConnectionDot client={c} />
            <span className="min-w-0 truncate font-mono text-xs text-ink-muted">
              {c.hostname} · {c.os}/{c.arch} · {c.agentVersion}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button asChild>
              <Link to="/o/$org/clients/$id/$tab" params={{ org: orgSlug, id: clientId, tab: 'certificates' }} search={{ grant: 'new' }}>
                Grant certificate
              </Link>
            </Button>
            <Button asChild variant="outline">
              <Link to="/o/$org/clients/$id" params={{ org: orgSlug, id: clientId }}>
                Open client
              </Link>
            </Button>
          </div>
        </>
      ) : expired ? (
        <div className="flex flex-wrap items-center gap-3">
          <ToneChip tone="expired" icon={CircleX} label="Token expired" />
          <Button disabled={renewing} onClick={onNewToken}>
            New token
          </Button>
        </div>
      ) : (
        <p className="flex items-center gap-2 text-sm">
          <LoaderCircle className="size-4 animate-spin text-pending motion-reduce:animate-none" aria-hidden />
          {c?.status === 'active' ? 'Enrolled, waiting for the connection' : 'Waiting for agent'}
          <HelpTip id="client.waiting" />
        </p>
      )}
      {q.isError && (
        <p role="alert" className="text-sm">
          {errorMessage(q.error)}
        </p>
      )}
    </section>
  );
}
