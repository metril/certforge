import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { createColumnHelper } from '@tanstack/react-table';
import { Plus, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { useCheckMonitor, monitorsQuery } from '@/api/queries/monitors';
import type { Monitor } from '@/api/types';
import { CopyField } from '@/components/CopyField';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { PrimaryCell } from '@/components/PrimaryCell';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { help } from '@/lib/help';
import { failedWithoutData } from '@/lib/queryState';
import { fmtInterval, shortFp } from '@/lib/monitors';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { AlertsHeader } from './AlertsLayout';
import { MonitorSheet } from './MonitorSheet';
import { MonitorStateChip } from './MonitorStateChip';

const col = createColumnHelper<Monitor>();
const MONITOR_LIMIT = 500;

function CheckNowButton({ monitor, orgId }: { monitor: Monitor; orgId: string }) {
  const me = useMe();
  const check = useCheckMonitor(orgId);
  const allowed = can(me, 'alerts:write', orgId);
  return (
    <PermissionTip allowed={allowed} action="alerts:write">
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        aria-label={`Check ${monitor.name} now`}
        disabled={!allowed || check.isPending}
        onClick={(e) => {
          e.stopPropagation();
          check.mutate(monitor.id, {
            onError: (err) => toast.error(errorMessage(err)),
          });
        }}
      >
        <RefreshCw className={check.isPending ? 'size-4 animate-spin' : 'size-4'} aria-hidden />
      </Button>
    </PermissionTip>
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
      cell: ({ row }) => <PrimaryCell primary={row.original.name} meta={monitorMeta(row.original)} />,
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
      className="relative grid gap-2 rounded-md border border-border bg-panel p-3 hover:bg-subtle"
    >
      <div className="flex items-center justify-between gap-2">
        <button type="button" onClick={onOpen} className="truncate text-left font-semibold after:absolute after:inset-0 after:content-[''] focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-ring/50 focus-visible:after:rounded-md">
          {monitor.name}
        </button>
        <span className="relative z-10">
          <CheckNowButton monitor={monitor} orgId={orgId} />
        </span>
      </div>
      <TargetCell monitor={monitor} />
      <div className="flex flex-wrap items-center gap-2">
        <MonitorStateChip state={monitor.state} enabled={monitor.enabled} lastError={monitor.lastError} notAfter={monitor.lastNotAfter} />
        <span className="text-xs text-ink-muted">{fmtInterval(monitor.intervalSeconds)}</span>
      </div>
      {monitor.lastFingerprint && (
        <div className="relative z-10 w-fit max-w-full">
          <CopyField value={monitor.lastFingerprint} label="fingerprint" display={shortFp(monitor.lastFingerprint)} />
        </div>
      )}
      <NextCheckCell monitor={monitor} />
    </div>
  );
}

export function MonitorsPage() {
  const org = useOrg();
  const me = useMe();
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const { edit } = useSearch({ from: '/_app/o/$org/alerts/monitors' });
  const navigate = useNavigate({ from: '/o/$org/alerts/monitors' });
  const q = useQuery(monitorsQuery(org.id));
  const monitors = q.data ?? [];
  const canWrite = can(me, 'alerts:write', org.id);
  const atLimit = monitors.length >= MONITOR_LIMIT;
  const addAllowed = canWrite && !atLimit;
  const openSheet = (id: string | undefined) =>
    void navigate({
      search: (prev) => ({ ...prev, edit: id }),
      replace: id === undefined,
    });
  const columns = useMemo(() => monitorColumns(org.id), [org.id]);
  const editing = monitors.find((m) => m.id === edit);
  const editNotFound = !q.isPending && !q.isError && !!edit && edit !== 'new' && !editing;

  const add = (
    <PermissionTip allowed={addAllowed} action="alerts:write" reason={!canWrite ? undefined : atLimit ? help['monitor.limit'].text : undefined}>
      <Button disabled={!addAllowed} onClick={() => openSheet('new')}>
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
              <DataTable ariaLabel="Monitors" data={monitors} columns={columns} getRowId={(m) => m.id} onRowClick={(id) => openSheet(id)} />
            ) : (
              <div className="grid gap-2">
                {monitors.map((m) => (
                  <MonitorCard key={m.id} monitor={m} orgId={org.id} onOpen={() => openSheet(m.id)} />
                ))}
              </div>
            )}
          </>
        )}
        {(edit === 'new' || editing) && (
          <MonitorSheet key={edit} orgId={org.id} open monitor={editing} onOpenChange={(o) => !o && openSheet(undefined)} />
        )}
        {editNotFound && (
          <Sheet open onOpenChange={(o) => !o && openSheet(undefined)}>
            <SheetContent side="right" className="w-full sm:max-w-lg">
              <SheetHeader>
                <SheetTitle>Monitor not found</SheetTitle>
                <SheetDescription>It may have been deleted.</SheetDescription>
              </SheetHeader>
              <div className="px-4">
                <Button onClick={() => openSheet(undefined)}>Back to monitors</Button>
              </div>
            </SheetContent>
          </Sheet>
        )}
      </div>
    </>
  );
}
