import { useInfiniteQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { errorMessage } from '@/api/errors';
import { auditInfinite } from '@/api/queries/audit';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { actionTone } from '@/features/audit/actions';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { fmtDateTime, relTime } from '@/lib/time';

/** Audit events whose resource, details or actor carry this client's id. */
export function ActivityTab({ orgId, orgSlug, clientId }: { orgId: string; orgSlug: string; clientId: string }) {
  const me = useMe();
  const allowed = can(me, 'audit:read', orgId);
  const q = useInfiniteQuery({ ...auditInfinite({ orgId, q: clientId }), enabled: allowed });
  if (!allowed) return <EmptyState message="Needs the audit:read permission." />;
  if (q.isError) return <ErrorState message={`Couldn't load activity. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
  if (q.isPending) return <p className="text-ink-muted">Loading…</p>;
  const events = q.data.pages.flatMap((p) => p.items);
  const auditLink = (label: string) => (
    <Link to="/o/$org/audit" params={{ org: orgSlug }} search={{ q: clientId }} className="text-sm text-primary underline-offset-2 hover:underline">
      {label}
    </Link>
  );
  if (events.length === 0) {
    return (
      <EmptyState message="No activity yet.">
        <Button asChild variant="outline">
          <Link to="/o/$org/audit" params={{ org: orgSlug }}>
            Open audit log
          </Link>
        </Button>
      </EmptyState>
    );
  }
  return (
    <div className="grid gap-2">
      <div className="flex justify-end">{auditLink('Open in audit log')}</div>
      <ul aria-label="Client activity" className="grid">
        {events.map((e) => {
          const { tone, icon } = actionTone(e.action);
          return (
            <li key={e.id} className="grid gap-1 border-b border-border py-2 text-sm last:border-0 md:grid-cols-[96px_auto_minmax(0,160px)_minmax(0,1fr)] md:items-center md:gap-3">
              <time dateTime={e.ts} title={fmtDateTime(e.ts)} className="text-xs text-ink-muted">
                {relTime(e.ts, q.dataUpdatedAt)}
              </time>
              <Link to="/o/$org/audit" params={{ org: orgSlug }} search={{ event: e.id }} className="w-fit hover:underline">
                <ToneChip tone={tone} icon={icon} label={e.action} />
              </Link>
              <span className="truncate text-xs">{e.actorName || e.actorType}</span>
              <span className="truncate text-xs text-ink-muted">
                {e.resourceType} <span className="font-mono">{e.resourceId}</span>
              </span>
            </li>
          );
        })}
      </ul>
      {q.hasNextPage && (
        <Button variant="outline" className="w-fit" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
          Load more
        </Button>
      )}
    </div>
  );
}
