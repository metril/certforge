import { useQuery } from '@tanstack/react-query';
import { ShieldOff } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { rateLedgerQuery, RATE_LIMIT_LABEL } from '@/api/queries/rateLedger';
import { ErrorState } from '@/components/ErrorState';
import { ToneChip } from '@/components/StatusChip';
import { relTime } from '@/lib/time';
import { cn } from '@/lib/utils';

type Tone = 'valid' | 'expiring' | 'failed';

const FILL: Record<Tone, string> = {
  valid: 'bg-valid',
  expiring: 'bg-expiring',
  failed: 'bg-failed',
};

function meterTone(count: number, max: number): Tone {
  const pct = count / max;
  if (pct >= 1) return 'failed';
  if (pct >= 0.8) return 'expiring';
  return 'valid';
}

function SkeletonRow() {
  return (
    <li className="flex items-center gap-3" aria-hidden>
      <div className="h-3 w-36 animate-pulse rounded-sm bg-subtle" />
      <div className="h-1.5 flex-1 animate-pulse rounded-sm bg-subtle" />
    </li>
  );
}

/** Under a failed `rate_ledger` step: what CertForge's own local rate-limit
 * ledger currently shows for this certificate's CA, so a "5/5" failure has a
 * usage panel to point at instead of just the raw error text. */
export function RateLedgerPanel({ orgId, caId, certId }: { orgId: string; caId?: string | null; certId: string }) {
  const enabled = !!caId;
  const { data, isPending, isError, error, refetch } = useQuery({ ...rateLedgerQuery(orgId, caId ?? '', certId), enabled });
  if (!enabled) return null;
  if (isPending) {
    return (
      <ul aria-label="Rate limits" className="grid gap-2 py-1">
        <SkeletonRow />
        <SkeletonRow />
      </ul>
    );
  }
  if (isError) {
    return <ErrorState message={`Couldn't load rate limits. ${errorMessage(error)}`} onRetry={() => void refetch()} />;
  }
  return (
    <ul aria-label="Rate limits" className="grid gap-2 py-1 text-xs">
      {!data.enforced && (
        <li>
          <ToneChip tone="neutral" icon={ShieldOff} label="Counted only" help="rateLedger.enforced" />
        </li>
      )}
      {data.items.map((it) => (
        <li key={`${it.limit}-${it.scope}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 md:flex-nowrap">
          <span className="w-44 shrink-0">{RATE_LIMIT_LABEL[it.limit]}</span>
          <span className="max-w-40 truncate font-mono text-ink-muted" title={it.scope || undefined}>
            {it.scope || '—'}
          </span>
          {it.max > 0 ? (
            <>
              <div className="h-1.5 min-w-16 flex-1 bg-subtle">
                <div className={cn('h-full', FILL[meterTone(it.count, it.max)])} style={{ width: `${Math.min(100, (it.count / it.max) * 100)}%` }} />
              </div>
              <span className="font-mono">
                {it.count} / {it.max}
              </span>
              {it.resetsAt && <span className="text-ink-muted">resets {relTime(it.resetsAt)}</span>}
            </>
          ) : (
            <span className="text-ink-muted">No limit</span>
          )}
        </li>
      ))}
    </ul>
  );
}
