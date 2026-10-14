import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { Plus, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { useCheckMonitor, monitorsQuery } from '@/api/queries/monitors';
import type { Monitor } from '@/api/types';
import { EntityLink } from '@/components/EntityLink';
import { CopyField } from '@/components/CopyField';
import { columnHelper, DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { PrimaryCell } from '@/components/PrimaryCell';
import { PermissionTip } from '@/components/PermissionTip';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetBody } from '@/components/ui/sheet';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { help } from '@/lib/help';
import { failedWithoutData } from '@/lib/queryState';
import { fmtInterval, shortFp } from '@/lib/monitors';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { AlertsHeader } from './AlertsLayout';
import { MonitorStateChip } from './MonitorStateChip';
import { IconButton } from '@/components/IconButton';

const col = columnHelper<Monitor>();
export const MONITOR_LIMIT = 500;

function CheckNowButton({ monitor, orgId }: { monitor: Monitor; orgId: string }) {
  const me = useMe();
  const check = useCheckMonitor(orgId);
  const allowed = can(me, 'alerts:write', orgId);
  return (
    <IconButton tip={allowed ? undefined : `Needs the alerts:write permission`}
        type="button"
        variant="ghost"
        size="icon-sm"
        label={`Check ${monitor.name} now`}
        disabled={!allowed || check.isPending}
        onClick={(e) => {
          e.stopPropagation();
          check.mutate(monitor.id, {
            onError: (err) => toast.error(errorMessage(err)),
          });
        }}
      >
        <RefreshCw className={check.isPending ? 'size-4 animate-spin' : 'size-4'} aria-hidden />
      </IconButton>
  );
}

// Links to the owning server grant's row on its target's Grants tab.
function GrantBadge({ monitor }: { monitor: Monitor }) {
  const org = useOrg();
  const badge = <Badge variant="outline" tabIndex={monitor.grantDeployTargetId ? undefined : 0}>Grant</Badge>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {monitor.grantDeployTargetId && monitor.grantId ? (
          <Link to="/o/$org/delivery/targets/$id/$tab" params={{ org: org.slug, id: monitor.grantDeployTargetId, tab: 'grants' }} search={{ open: monitor.grantId }} onClick={(e) => e.stopPropagation()}>
            {badge}
          </Link>
        ) : (
          badge
        )}
      </TooltipTrigger>
      <TooltipContent>Owned by a server grant; change it in the grant's Verify settings.</TooltipContent>
    </Tooltip>
  );
}

function TargetCell({ monitor }: { monitor: Monitor }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <span className="truncate font-mono text-xs">
        {monitor.host}:{monitor.port}
      </span>
      {monitor.sni && <span className="truncate font-mono text-xs text-ink-muted">{monitor.sni}</span>}
    </div>
  );
}

function NextCheckCell({ monitor }: { monitor: Monitor }) {
  if (!monitor.nextCheckAt) return <span className="text-xs text-ink-muted">—</span>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="text-xs">
          {relTime(monitor.nextCheckAt)}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">{monitor.lastCheckedAt ? `Last checked ${relTime(monitor.lastCheckedAt)}` : 'Never checked'}</TooltipContent>
    </Tooltip>
  );
}

function monitorMeta(m: Monitor): string[] {
  return [`${m.host}:${m.port}`, m.sni, fmtInterval(m.intervalSeconds), m.lastFingerprint ? shortFp(m.lastFingerprint) : ''].filter((x): x is string => !!x);
}

function monitorColumns(orgId: string) {
  return [
    col.accessor('name', {
      header: 'Name',
      cell: ({ row }) => (
        <span className="flex items-center gap-2">
          <PrimaryCell primary={row.original.name} meta={monitorMeta(row.original)} />
          {row.original.grantId && <GrantBadge monitor={row.original} />}
        </span>
      ),
    }),
    col.display({
      id: 'state',
      header: 'State',
      meta: { className: 'w-32' },
      cell: ({ row }) => <MonitorStateChip state={row.original.state} enabled={row.original.enabled} lastError={row.original.lastError} notAfter={row.original.lastNotAfter} />,
    }),
    col.display({
      id: 'nextCheck',
      header: 'Next check',
      meta: { className: 'w-28' },
      cell: ({ row }) => <NextCheckCell monitor={row.original} />,
    }),
    col.display({
      id: 'check',
      header: () => <span className="sr-only">Check now</span>,
      meta: { className: 'w-16' },
      cell: ({ row }) => <CheckNowButton monitor={row.original} orgId={orgId} />,
    }),
  ];
}

function MonitorCard({ monitor, orgId, onOpen }: { monitor: Monitor; orgId: string; onOpen: () => void }) {
  return (
    <div
      className={`relative grid gap-2 rounded-md border border-border bg-panel p-3${monitor.grantId ? '' : ' hover:bg-subtle'}`}
    >
      <div className="flex items-center justify-between gap-2">
        {monitor.grantId ? (
          <span className="truncate font-semibold">{monitor.name}</span>
        ) : (
          <button type="button" onClick={onOpen} className="truncate text-left font-semibold after:absolute after:inset-0 after:content-[''] focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-ring/50 focus-visible:after:rounded-md">
            {monitor.name}
          </button>
        )}
        <span className="relative z-10">
          <CheckNowButton monitor={monitor} orgId={orgId} />
        </span>
      </div>
      <TargetCell monitor={monitor} />
      <div className="flex flex-wrap items-center gap-2">
        {/* z-10: the title's stretched overlay must not cover the chip's tooltip trigger. */}
        <span className="relative z-10">
          <MonitorStateChip state={monitor.state} enabled={monitor.enabled} lastError={monitor.lastError} notAfter={monitor.lastNotAfter} />
        </span>
        <span className="text-xs text-ink-muted">{fmtInterval(monitor.intervalSeconds)}</span>
        {monitor.grantId && (
          <span className="relative z-10">
            <GrantBadge monitor={monitor} />
          </span>
        )}
      </div>
      {monitor.lastFingerprint && (
        <div className="relative z-10 w-fit max-w-full">
          <CopyField value={monitor.lastFingerprint} label="fingerprint" display={shortFp(monitor.lastFingerprint)} />
        </div>
      )}
      <span className="relative z-10 w-fit">
        <NextCheckCell monitor={monitor} />
      </span>
    </div>
  );
}

export function MonitorsPage() {
  const org = useOrg();
  const me = useMe();
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const { managed: managedId } = useSearch({ from: '/_app/o/$org/alerts/monitors/' });
  const navigate = useNavigate();
  const q = useQuery(monitorsQuery(org.id));
  const monitors = q.data ?? [];
  const canWrite = can(me, 'alerts:write', org.id);
  const atLimit = monitors.length >= MONITOR_LIMIT;
  const addAllowed = canWrite && !atLimit;
  // A grant-owned monitor is edited through its grant: its rows are inert and `?managed=` opens a read-only sheet.
  const openManaged = (id: string | undefined) => void navigate({ to: '/o/$org/alerts/monitors', params: { org: org.slug }, search: id ? { managed: id } : {}, replace: id === undefined });
  const openEdit = (id: string) => void navigate({ to: '/o/$org/alerts/monitors/$id/edit', params: { org: org.slug, id } });
  const rowClick = (id: string) => (monitors.find((m) => m.id === id)?.grantId ? undefined : openEdit(id));
  const columns = useMemo(() => monitorColumns(org.id), [org.id]);
  const managed = monitors.find((m) => m.id === managedId && m.grantId);

  const add = (
    <PermissionTip allowed={addAllowed} action="alerts:write" reason={!canWrite ? undefined : atLimit ? help['monitor.limit'].text : undefined}>
      <Button disabled={!addAllowed} onClick={() => void navigate({ to: '/o/$org/alerts/monitors/new', params: { org: org.slug } })}>
        <Plus className="size-4" aria-hidden />
        Add monitor
      </Button>
    </PermissionTip>
  );

  return (
    <>
      <AlertsHeader help="alerts.monitors" actions={q.isPending || failedWithoutData(q) || monitors.length === 0 ? undefined : add} />
      <div className="grid gap-4">
        {q.isPending ? (
          <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
        ) : failedWithoutData(q) ? (
          <ErrorState message={`Couldn't load monitors. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
        ) : monitors.length === 0 ? (
          <EmptyState message="No monitors yet.">{add}</EmptyState>
        ) : (
          <>
            {isMdUp ? (
              <DataTable ariaLabel="Monitors" data={monitors} columns={columns} getRowId={(m) => m.id} onRowClick={rowClick} />
            ) : (
              <div className="grid gap-2">
                {monitors.map((m) => (
                  <MonitorCard key={m.id} monitor={m} orgId={org.id} onOpen={() => rowClick(m.id)} />
                ))}
              </div>
            )}
          </>
        )}
        {managed && (
          <Sheet open onOpenChange={(o) => !o && openManaged(undefined)}>
            <SheetContent side="right" size="xl">
              <SheetHeader>
                <SheetTitle>Managed by a server grant</SheetTitle>
                <SheetDescription>{managed.name}</SheetDescription>
              </SheetHeader>
              <SheetBody>
                <dl className="grid gap-2 text-sm">
                  <div>
                    <dt className="text-xs text-ink-muted">Endpoint</dt>
                    <dd className="font-mono">
                      {managed.host}:{managed.port}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-ink-muted">Interval</dt>
                    <dd>{fmtInterval(managed.intervalSeconds)}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-ink-muted">Expected certificate</dt>
                    <dd>
                      {managed.expectedCertificateName ? (
                        <EntityLink kind="certificate" id={managed.expectedCertificateId}>
                          {managed.expectedCertificateName}
                        </EntityLink>
                      ) : (
                        'Any current certificate in the org'
                      )}
                    </dd>
                  </div>
                </dl>
                <p className="text-sm text-ink-muted">This monitor is edited on its grant: Delivery, then the target, then Grants.</p>
                <div className="flex gap-2">
                  <Button asChild>
                    <Link to="/o/$org/delivery/targets" params={{ org: org.slug }}>
                      Go to Delivery targets
                    </Link>
                  </Button>
                  <Button variant="outline" onClick={() => openManaged(undefined)}>
                    Close
                  </Button>
                </div>
              </SheetBody>
            </SheetContent>
          </Sheet>
        )}
      </div>
    </>
  );
}
