import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert, CircleCheck, CircleX, Clock, FileDiff, Hourglass, Radar, WifiOff, type LucideIcon } from 'lucide-react';
import { allCertificatesQuery, allOrgsCertificatesQuery, useRenewCertificates } from '@/api/queries/certificates';
import { allClientsQuery } from '@/api/queries/clients';
import { agentCAsQuery } from '@/api/queries/agents';
import { monitorsQuery, useCheckMonitor } from '@/api/queries/monitors';
import { errorMessage } from '@/api/errors';
import { readinessQuery } from '@/api/queries/health';
import type { Certificate, Client } from '@/api/types';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PageHeader } from '@/components/PageHeader';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { CertValidity } from '@/components/ValidityBar';
import { Button } from '@/components/ui/button';
import { ManualDnsCard } from '@/features/certificates/ManualDnsCard';
import { can, canAnywhere } from '@/lib/permissions';
import { renewToastHandlers } from '@/lib/renewToast';
import { useAllOrgs, useMe, useOrg, useOrgSlugOf } from '@/lib/org';
import type { Tone } from '@/lib/status';
import { DAY, relDays } from '@/lib/time';
import { toast } from 'sonner';
import { attentionItems, statusCounts, upcomingRenewals, usesManualDns, type AttentionKind } from './attention';
import { attentionQueue, clientAttentionItems, type ClientAttentionKind } from './clientAttention';
import { ExpiryHorizon } from './ExpiryHorizon';
import { HealthStrip } from './HealthStrip';
import { monitorAttentionItems, type MonitorAttentionKind } from './monitorAttention';
import { RecentActivity } from './RecentActivity';

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
};
// Deviations "Overview rows": only mismatch and unreachable, single-org only.
const MONITOR_KIND: Record<MonitorAttentionKind, { tone: Tone; label: string }> = {
  'monitor-mismatch': { tone: 'failed', label: 'Mismatch' },
  'monitor-unreachable': { tone: 'failed', label: 'Unreachable' },
};
const TILES = [
  { status: 'active', label: 'Active', icon: CircleCheck, cls: 'text-valid' },
  { status: 'pending', label: 'Pending', icon: Hourglass, cls: 'text-pending' },
  { status: 'failed', label: 'Failed', icon: CircleAlert, cls: 'text-failed' },
  { status: 'expired', label: 'Expired', icon: CircleX, cls: 'text-expired' },
] as const;

// Below `md` this is a card row (name, then validity and the right-hand
// note stacked); at `md` and up it's a three-column line, per the phone
// layout carry-in (queue and renewals render as card rows below md).
function CertRow({ cert, org, right }: { cert: Certificate; org: string; right: React.ReactNode }) {
  return (
    <li className="grid gap-1 border-b border-border py-2 text-sm md:h-9 md:grid-cols-[minmax(0,1fr)_128px_auto] md:items-center md:gap-4 md:py-0">
      <Link to="/o/$org/certificates/$id/$tab" params={{ org, id: cert.id, tab: 'overview' }} className="truncate font-semibold hover:underline">
        {cert.name}
      </Link>
      <CertValidity cert={cert} />
      <span className="whitespace-nowrap text-ink-muted">{right}</span>
    </li>
  );
}

export function OverviewPage() {
  const org = useOrg();
  const allOrgs = useAllOrgs();
  const slugOf = useOrgSlugOf();
  const me = useMe();
  const { data: certs = [], isPending, isError, error, refetch } = useQuery(allOrgs ? allOrgsCertificatesQuery : allCertificatesQuery(org.id));
  const readiness = useQuery(readinessQuery);
  const canClients = allOrgs ? canAnywhere(me, 'clients:read') : can(me, 'clients:read', org.id);
  // org.id is 'all' under All orgs, which allClientsQuery maps to GET /clients.
  const clients = useQuery({ ...allClientsQuery(org.id), enabled: canClients });
  const agentCAs = useQuery({ ...agentCAsQuery, enabled: can(me, 'settings:read') });
  // Deviations "Overview rows": monitor mismatch/unreachable rows exist only
  // in a single-org view — there is no cross-org monitor list.
  const canMonitors = !allOrgs && can(me, 'alerts:read', org.id);
  const monitors = useQuery({ ...monitorsQuery(org.id), enabled: canMonitors });
  const checkMonitor = useCheckMonitor(org.id);
  const renew = useRenewCertificates(org.id);
  const search = useSearch({ from: '/_app/o/$org/overview' });
  const navigate = useNavigate({ from: '/o/$org/overview' });
  const range = search.range ?? null;
  const setRange = (r: [number, number] | null) => void navigate({ search: (prev) => ({ ...prev, range: r ?? undefined }), replace: true });
  const now = Date.now();
  const slug = (c: Certificate) => (allOrgs ? slugOf(c.orgId) : org.slug);

  if (isError) {
    return (
      <>
        <PageHeader title="Overview" />
        <ErrorState message={`Couldn't load certificates. ${errorMessage(error)}`} onRetry={() => void refetch()} />
      </>
    );
  }

  if (!isPending && certs.length === 0) {
    return (
      <>
        <PageHeader title="Overview" />
        <div className="grid gap-6">
          <HealthStrip readiness={readiness.data} listener={agentCAs.data?.listener} />
          <EmptyState message="No certificates yet.">
            {!allOrgs &&
              (can(me, 'certs:write', org.id) ? (
                <Button asChild>
                  <Link to="/o/$org/certificates/new" params={{ org: org.slug }}>
                    New certificate
                  </Link>
                </Button>
              ) : (
                <PermissionTip allowed={false} action="certs:write">
                  <Button disabled>New certificate</Button>
                </PermissionTip>
              ))}
          </EmptyState>
        </div>
      </>
    );
  }

  const items = attentionItems(certs, now);
  const others = items.filter((i) => i.kind !== 'manual-dns');
  // Controller ruling: a card is mounted for every non-revoked,
  // non-expired certificate whose rules use manual-dns, regardless of
  // `status` — a renewal of an already-`active` certificate still waiting
  // on TXT records must show, not just a first-issuance `pending` one.
  // Whether a given card actually has records to show isn't knowable from
  // this list (that's `ManualDnsCard`'s own fetch); the `manual-dns`
  // *attention item* above stays `pending`-only, so the queue's own count
  // doesn't double-count a cert this section already surfaces its own way.
  const manualDnsCerts = certs.filter((c) => c.status !== 'revoked' && c.status !== 'expired' && usesManualDns(c));
  const clientItems = clientAttentionItems(clients.data?.items ?? [], now);
  const monitorItems = canMonitors ? monitorAttentionItems(monitors.data ?? []) : [];
  const queue = attentionQueue(others, clientItems, monitorItems);
  const clientSlug = (c: Client) => (allOrgs ? slugOf(c.orgId) : org.slug);
  const counts = statusCounts(certs);
  const upcoming = upcomingRenewals(certs, now);
  const inRange = range
    ? certs.filter((c) => {
        if (!c.currentVersion) return false;
        const d = (Date.parse(c.currentVersion.notAfter) - now) / DAY;
        // Review fix: a range starting at 0 ("from now") also catches an
        // already-expired certificate (d < 0), not just d === 0 exactly.
        return (range[0] === 0 ? d <= range[1] : d >= range[0]) && d <= range[1];
      })
    : [];

  return (
    <>
      <PageHeader title="Overview" />
      <div className="grid gap-8">
        <HealthStrip readiness={readiness.data} listener={agentCAs.data?.listener} />
        <nav aria-label="Filter certificates by status" className="flex flex-wrap gap-2">
          {TILES.map((t) => (
            <Link
              key={t.status}
              to="/o/$org/certificates"
              params={{ org: org.slug }}
              search={{ status: t.status }}
              aria-label={`${counts[t.status]} ${t.label}`}
              className="inline-flex h-9 items-center gap-2 rounded-md border border-border px-3 text-sm hover:bg-subtle"
            >
              <t.icon className={`size-4 ${t.cls}`} aria-hidden />
              <span className="font-semibold tabular-nums">{counts[t.status]}</span>
              {t.label}
            </Link>
          ))}
        </nav>
        <section aria-label="Needs attention" className="grid gap-3">
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
                  return (
                    <li key={`${kind}-${c.id}`} className={row}>
                      <ToneChip tone={k.tone} icon={k.icon} label={k.label} />
                      <Link to="/o/$org/clients/$id/$tab" params={params} className="truncate font-semibold hover:underline">
                        {c.name}
                      </Link>
                      <span className="truncate text-ink-muted">{cause}</span>
                      {can(me, 'clients:write', c.orgId) && (
                        <Button size="sm" variant="outline" asChild>
                          <Link to="/o/$org/clients/$id/$tab" params={params}>
                            {k.fix}
                          </Link>
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
                            disabled={!canCheck || checkMonitor.isPending}
                            onClick={() => checkMonitor.mutate(m.id, { onError: (e) => toast.error(errorMessage(e)) })}
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
                      <Button size="sm" variant="outline" disabled={renew.isPending} onClick={() => renew.mutate([i.cert.id], renewToastHandlers(i.cert.name))}>
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
        </section>
        <ExpiryHorizon certs={certs} now={now} range={range} onRange={setRange} />
        {range && (
          <section aria-label="Expiring in range" className="grid gap-2">
            <div className="flex items-center gap-3">
              <h2 className="text-base font-semibold">
                Expiring in {range[0]} to {range[1]} days
              </h2>
              <Button variant="link" size="sm" onClick={() => setRange(null)}>
                Clear range
              </Button>
            </div>
            <ul className="grid">
              {inRange.map((c) => (
                <CertRow key={c.id} cert={c} org={slug(c)} right={relDays(c.currentVersion!.notAfter, now)} />
              ))}
            </ul>
          </section>
        )}
        <div className="grid gap-8 lg:grid-cols-2">
          <section aria-label="Upcoming renewals" className="grid content-start gap-2">
            <h2 className="text-base font-semibold">Upcoming renewals</h2>
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
          <RecentActivity orgId={allOrgs ? undefined : org.id} />
        </div>
      </div>
    </>
  );
}
