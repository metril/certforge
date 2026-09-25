import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { errorMessage } from '@/api/errors';
import { recentActivityQuery } from '@/api/queries/audit';
import { usersQuery } from '@/api/queries/users';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { ToneChip } from '@/components/StatusChip';
import { actionTone } from '@/features/audit/actions';
import { useActiveOrgSlug, useMe } from '@/lib/org';
import { can, canAnywhere } from '@/lib/permissions';
import { fmtDateTime, relTime } from '@/lib/time';

/** Last 20 audit events; orgId undefined means every org (All orgs). Only
 * rendered when the caller can read the audit log there (or anywhere,
 * under All orgs) — omitted otherwise, never an error. */
export function RecentActivity({ orgId }: { orgId?: string }) {
  const me = useMe();
  const slug = useActiveOrgSlug() ?? '';
  const allowed = orgId ? can(me, 'audit:read', orgId) : canAnywhere(me, 'audit:read');
  const canUsers = allowed && canAnywhere(me, 'users:read');
  const q = useQuery({ ...recentActivityQuery(orgId), enabled: allowed });
  const users = useQuery({ ...usersQuery, enabled: canUsers });
  if (!allowed) return null;

  // Never a raw id when a name is available: resolve to the user's current
  // display name only when users:read is allowed, otherwise fall back to
  // the audit event's own recorded name, and only then its actor type
  // (fix round 2, Important #2 — this used to show the raw actorId whenever
  // canUsers was false, even though every AuditEvent already carries a
  // human-readable actorName).
  const actor = (e: { actorId: string; actorName: string; actorType: string }) => {
    const name = (canUsers && users.data?.find((u) => u.id === e.actorId)?.displayName) || e.actorName || e.actorType;
    return <span className="truncate">{name}</span>;
  };

  return (
    <section aria-label="Recent activity" className="grid content-start gap-2">
      <h2 className="flex items-center gap-1.5 text-base font-semibold">
        Recent activity <HelpTip id="overview.activity" />
        <Link to="/o/$org/audit" params={{ org: slug }} className="ml-auto text-sm font-normal text-primary underline-offset-2 hover:underline">
          Audit log
        </Link>
      </h2>
      {q.isError ? (
        <ErrorState message={`Couldn't load recent activity. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : q.data?.length === 0 ? (
        <p className="text-sm text-ink-muted">No activity yet.</p>
      ) : (
        <ul className="grid">
          {(q.data ?? []).map((e) => {
            const { tone, icon: Icon } = actionTone(e.action);
            return (
              <li key={e.id} className="grid gap-1 border-b border-border py-2 text-sm last:border-0">
                <div className="flex flex-wrap items-center gap-2">
                  {/* dataUpdatedAt (not Date.now()) so an identical-data poll
                      still re-renders this label — the query result object
                      itself only changes reference when the timestamp does. */}
                  <time dateTime={e.ts} title={fmtDateTime(e.ts)} className="shrink-0 text-xs text-ink-muted">
                    {relTime(e.ts, q.dataUpdatedAt)}
                  </time>
                  <Link to="/o/$org/audit" params={{ org: slug }} search={{ event: e.id }} className="min-w-0 hover:underline">
                    <ToneChip tone={tone} icon={Icon} label={e.action} />
                  </Link>
                  <span className="min-w-0 truncate text-xs text-ink-muted">{actor(e)}</span>
                </div>
                <span className="truncate text-xs text-ink-muted">
                  {e.resourceType} <span className="font-mono">{e.resourceId}</span>
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
