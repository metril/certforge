import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert, CircleCheck, CircleX, Clock, FileDiff, Hourglass, Radar, WifiOff, type LucideIcon } from 'lucide-react';
import { allClientsQuery } from '@/api/queries/clients';
import { usePendingApprovals } from '@/api/queries/enrollments';
import { monitorsQuery, useCheckMonitor } from '@/api/queries/monitors';
import { useRenewCertificates } from '@/api/queries/certificates';
import { errorMessage } from '@/api/errors';
import type { CertBrief, Client } from '@/api/types';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { ManualDnsCard } from '@/features/certificates/ManualDnsCard';
import { can, canAnywhere } from '@/lib/permissions';
import { renewToastHandlers } from '@/lib/renewToast';
import { useAllOrgs, useMe, useOrg, useOrgSlugOf } from '@/lib/org';
import type { Tone } from '@/lib/status';
import { relDays } from '@/lib/time';
import { usePendingIds } from '@/lib/usePendingIds';
import { toast } from 'sonner';
import { attentionItems, upcomingRenewals, type AttentionKind } from '../attention';
import { attentionQueue, clientAttentionItems, type ClientAttentionKind } from '../clientAttention';
import { monitorAttentionItems, type MonitorAttentionKind } from '../monitorAttention';
import { CertRow } from './CertRow';

const KIND: Record<AttentionKind, { tone: Tone; icon: LucideIcon; label: string }> = {
  expired: { tone: 'expired', icon: CircleX, label: 'Expired' },
  'manual-dns': { tone: 'pending', icon: Hourglass, label: 'Manual DNS' },
  failed: { tone: 'failed', icon: CircleAlert, label: 'Failed' },
  overdue: { tone: 'expiring', icon: Clock, label: 'Overdue' },
};
const CLIENT_KIND: Record<ClientAttentionKind, { tone: Tone; icon: LucideIcon; label: string; tab: 'certificates' | 'settings'; fix: string }> = {
  'deploy-failed': { tone: 'failed', icon: CircleAlert, label: 'Deploy failed', tab: 'certificates', fix: 'Review' },
  drift: { tone: 'drift', icon: FileDiff, label: 'Drift', tab: 'certificates', fix: 'Review' },
  offline: { tone: 'neutral', icon: WifiOff, label: 'Offline', tab: 'certificates', fix: 'Open' },
  'agent-cert': { tone: 'expiring', icon: Clock, label: 'Agent certificate', tab: 'settings', fix: 'Re-enrol' },
  'awaiting-approval': { tone: 'pending', icon: Hourglass, label: 'Awaiting approval', tab: 'certificates', fix: 'Review' },
};
// Deviations "Overview rows": only mismatch and unreachable, single-org only.
const MONITOR_KIND: Record<MonitorAttentionKind, { tone: Tone; label: string }> = {
  'monitor-mismatch': { tone: 'failed', label: 'Mismatch' },
  'monitor-unreachable': { tone: 'failed', label: 'Unreachable' },
};

/** Block 2: everything that wants a look (attention queue, manual-DNS cards,
 * client and monitor rows) with the next 7 days of renewals underneath. */
export function AttentionBlock({ certs, now }: { certs: CertBrief[]; now: number }) {
  const org = useOrg();
  const allOrgs = useAllOrgs();
  const slugOf = useOrgSlugOf();
  const me = useMe();
  const canClients = allOrgs ? canAnywhere(me, 'clients:read') : can(me, 'clients:read', org.id);
  // org.id is 'all' under All orgs, which allClientsQuery maps to GET /clients.
  const clients = useQuery({ ...allClientsQuery(org.id), enabled: canClients });
  // Deviations "Overview rows": monitor mismatch/unreachable rows exist only
  // in a single-org view — there is no cross-org monitor list.
  const canMonitors = !allOrgs && can(me, 'alerts:read', org.id);
  const monitors = useQuery({ ...monitorsQuery(org.id), enabled: canMonitors });
  const checkMonitor = useCheckMonitor(org.id);
  const renew = useRenewCertificates(org.id);
  const checking = usePendingIds();
  const renewing = usePendingIds();
  // Toast from the promise: with parallel rows only the latest mutation's
  // per-call callbacks fire, so an earlier row's result would be lost.
  const renewRow = (id: string, name: string) => {
    const h = renewToastHandlers(name);
    return renew.mutateAsync([id]).then(h.onSuccess, (e: unknown) => {
      h.onError(e);
      throw e;
    });
  };
  const slug = (c: CertBrief) => (allOrgs ? slugOf(c.orgId) : org.slug);
  const items = attentionItems(certs, now);
  const others = items.filter((i) => i.kind !== 'manual-dns');
  // Controller ruling: a card is mounted for every non-revoked,
  // non-expired certificate whose rules use manual-dns, regardless of
  // `status` — a renewal of an already-`active` certificate still waiting
  // on TXT records must show, not just a first-issuance `pending` one.
  // The `manual-dns` *attention item* stays `pending`-only, so the count
  // doesn't double-count a cert this section already surfaces its own way.
  const manualDnsCerts = certs.filter((c) => c.status !== 'revoked' && c.status !== 'expired' && c.manualDns);
  const approvals = usePendingApprovals(org.id, !allOrgs && can(me, 'clients:write', org.id));
  const clientItems = clientAttentionItems(clients.data?.items ?? [], now, approvals);
  const monitorItems = canMonitors ? monitorAttentionItems(monitors.data ?? []) : [];
  const queue = attentionQueue(others, clientItems, monitorItems);
  const clientSlug = (c: Client) => (allOrgs ? slugOf(c.orgId) : org.slug);
  const upcoming = upcomingRenewals(certs, now);
  return (
        <section aria-label="Needs attention" className="grid gap-3 rounded-lg border border-border bg-panel p-4">
          <h2 className="flex items-center gap-1.5 text-base font-semibold">
            Needs attention <HelpTip id="overview.attention" />
            <span className="text-sm font-normal text-ink-muted">{items.length + clientItems.length + monitorItems.length}</span>
          </h2>
          {!allOrgs &&
            manualDnsCerts.map((c) => <ManualDnsCard key={c.id} orgId={org.id} cert={c} canConfirm={can(me, 'certs:issue', org.id)} />)}
          {canClients && clients.data?.truncated && (
            <p className="text-xs text-ink-muted">Client checks cover the first {clients.data.items.length} clients only.</p>
          )}
          {queue.length > 0 ? (
            <ul className="grid">
              {queue.map((q) => {
                const row = 'grid min-h-9 grid-cols-1 items-center gap-2 border-b border-border py-2 text-sm md:grid-cols-[auto_minmax(0,160px)_minmax(0,1fr)_auto] md:gap-4 md:py-1';
                if (q.type === 'client') {
                  const { client: c, cause, kind } = q.item;
                  const k = CLIENT_KIND[kind];
                  const params = { org: clientSlug(c), id: c.id, tab: k.tab };
                  const fixLink =
                    kind === 'awaiting-approval' ? (
                      <Link to="/o/$org/clients" params={{ org: clientSlug(c) }} hash="approvals">
                        {k.fix}
                      </Link>
                    ) : (
                      <Link to="/o/$org/clients/$id/$tab" params={params}>
                        {k.fix}
                      </Link>
                    );
                  return (
                    <li key={`${kind}-${c.id}`} className={row}>
                      <ToneChip tone={k.tone} icon={k.icon} label={k.label} />
                      <Link to="/o/$org/clients/$id/$tab" params={params} className="truncate font-semibold hover:underline">
                        {c.name}
                      </Link>
                      <span className="truncate text-ink-muted">{cause}</span>
                      {can(me, 'clients:write', c.orgId) && (
                        <Button size="sm" variant="outline" asChild>
                          {fixLink}
                        </Button>
                      )}
                    </li>
                  );
                }
                if (q.type === 'monitor') {
                  const { monitor: m, cause, kind } = q.item;
                  const k = MONITOR_KIND[kind];
                  const canCheck = can(me, 'alerts:write', m.orgId);
                  return (
                    <li key={`${kind}-${m.id}`} className={row}>
                      <ToneChip tone={k.tone} icon={Radar} label={k.label} />
                      <Link to="/o/$org/alerts/monitors" params={{ org: org.slug }} search={{ edit: m.id }} className="truncate font-semibold hover:underline">
                        {m.name}
                      </Link>
                      <span className="flex min-w-0 flex-wrap items-center gap-2 truncate text-ink-muted">
                        <span className="shrink-0 font-mono text-xs">
                          {m.host}:{m.port}
                        </span>
                        <span className="truncate">{cause}</span>
                      </span>
                      <span className="inline-flex items-center gap-1">
                        <PermissionTip allowed={canCheck} action="alerts:write">
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={!canCheck || checking.isPending(m.id)}
                            onClick={() => void checking.track(m.id, checkMonitor.mutateAsync(m.id).catch((e: unknown) => { toast.error(errorMessage(e)); throw e; }))}
                          >
                            Check now
                          </Button>
                        </PermissionTip>
                        <HelpTip id="attention.monitor" />
                      </span>
                    </li>
                  );
                }
                const i = q.item;
                const k = KIND[i.kind];
                return (
                  <li key={i.cert.id} className={row}>
                    <ToneChip tone={k.tone} icon={k.icon} label={k.label} />
                    <Link to="/o/$org/certificates/$id/$tab" params={{ org: slug(i.cert), id: i.cert.id, tab: 'attempts' }} className="truncate font-semibold hover:underline">
                      {i.cert.name}
                    </Link>
                    <span className="truncate text-ink-muted">{i.cause}</span>
                    {!allOrgs && can(me, 'certs:issue', org.id) && (
                      <Button size="sm" variant="outline" disabled={renewing.isPending(i.cert.id)} onClick={() => void renewing.track(i.cert.id, renewRow(i.cert.id, i.cert.name))}>
                        Renew now
                      </Button>
                    )}
                  </li>
                );
              })}
            </ul>
          ) : canClients && clients.isError ? (
            <ErrorState message={`Couldn't check clients. ${errorMessage(clients.error)}`} onRetry={() => void clients.refetch()} />
          ) : (
            (allOrgs || manualDnsCerts.length === 0) && (
              <p className="flex items-center gap-1.5 text-sm">
                <CircleCheck className="size-4 text-valid" aria-hidden />
                Nothing needs attention.
              </p>
            )
          )}
          <section aria-label="Upcoming renewals" className="grid content-start gap-1 pt-2">
            <h3 className="text-sm font-semibold">Upcoming renewals</h3>
            {upcoming.length ? (
              <ul className="grid">
                {upcoming.map((c) => (
                  <CertRow key={c.id} cert={c} org={slug(c)} right={relDays(c.nextRenewAt!, now)} />
                ))}
              </ul>
            ) : (
              <p className="text-sm text-ink-muted">No renewals in the next 7 days.</p>
            )}
          </section>
        </section>
  );
}
