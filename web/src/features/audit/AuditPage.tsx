import { useEffect, useMemo, useRef, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Download, Info, Search, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import type { AuditEvent } from '@/api/types';
import { ApiError, errorMessage } from '@/api/errors';
import { auditEventQuery, auditInfinite, exportAudit } from '@/api/queries/audit';
import { usersQuery } from '@/api/queries/users';
import { Combobox } from '@/components/Combobox';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { FilterField } from '@/components/FilterToolbar';
import { FilterChips } from '@/components/FilterChips';
import { PageHeader } from '@/components/PageHeader';
import { SavedViews } from '@/components/SavedViews';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useAllOrgs, useMe, useOrg } from '@/lib/org';
import { can, canAnywhere } from '@/lib/permissions';
import { fmtDateTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { actionLabel, actionOptions, AUDIT_RESOURCE_TYPES } from './actions';
import { ChainStatus } from './ChainStatus';
import { auditColumns } from './columns';
import { EventSheet } from './EventSheet';
import { auditSearch, toApiFilter, type AuditSearch } from './search';

// D5: card rows below `md`, no horizontal overflow at 375px.
function AuditCard({ event, orgName }: { event: AuditEvent; orgName?: string }) {
  return (
    <div className="grid gap-1.5 rounded-md border border-border bg-panel p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-xs">{event.action}</span>
        <span className="shrink-0 font-mono text-xs text-ink-muted">{fmtDateTime(event.ts)}</span>
      </div>
      <div className="flex items-center justify-between gap-2 text-xs text-ink-muted">
        <span className="truncate">{event.actorName || event.actorType}</span>
        {orgName && <span className="shrink-0 truncate">{orgName}</span>}
      </div>
      <div className="truncate text-xs">
        {event.resourceType} <span className="font-mono text-ink-muted">{event.resourceId}</span>
      </div>
    </div>
  );
}

function AuditCardSkeleton() {
  return (
    <div className="grid gap-1.5 rounded-md border border-border bg-panel p-3" aria-hidden>
      <div className="h-3 w-32 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-20 animate-pulse rounded-sm bg-subtle" />
    </div>
  );
}

export function AuditPage() {
  const me = useMe();
  const org = useOrg();
  const allOrgs = useAllOrgs();
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const search = useSearch({ from: '/_app/o/$org/audit' });
  const navigate = useNavigate({ from: '/o/$org/audit' });
  const allowed = allOrgs ? canAnywhere(me, 'audit:read') : can(me, 'audit:read', org.id);
  // VerifyAuditChain needs global audit:read: an org-scoped auditor gets
  // 403 even for their own org, so the chip (and its request) is only
  // shown to a caller who actually has it.
  const canVerifyChain = can(me, 'audit:read', null);
  const filter = useMemo(() => toApiFilter(search, allOrgs ? undefined : org.id), [search, allOrgs, org.id]);
  const list = useInfiniteQuery({ ...auditInfinite(filter), enabled: allowed });
  const users = useQuery({ ...usersQuery, enabled: allowed && canAnywhere(me, 'users:read') });
  const [text, setText] = useState(search.q ?? '');
  const [exporting, setExporting] = useState(false);
  const [exportNotice, setExportNotice] = useState(false);
  const [exportError, setExportError] = useState(false);
  const [missingNotice, setMissingNotice] = useState(false);

  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const orgName = useMemo(() => (id: string | null) => (id === null ? 'Global' : (me.orgs.find((o) => o.id === id)?.name ?? id)), [me.orgs]);
  const columns = useMemo(() => auditColumns(allOrgs ? orgName : undefined), [allOrgs, orgName]);
  const set = (patch: Partial<AuditSearch>) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });
  const clear = () => void navigate({ search: {} });

  // Debounced, URL-synced text filter (controller ruling D5), mirroring
  // BindingsTab's own `q` debounce: `pushedQ` tracks the last value *this*
  // effect itself pushed to the URL, so an external change (saved view,
  // browser back/forward, a filter chip removal) is told apart from the
  // user still typing and syncs `text` instead of re-triggering a navigate.
  const pushedQ = useRef(search.q ?? '');
  useEffect(() => {
    const urlQ = search.q ?? '';
    if (urlQ !== pushedQ.current) {
      pushedQ.current = urlQ;
      if (urlQ !== text) setText(urlQ);
      return;
    }
    if (text === urlQ) return;
    const t = window.setTimeout(() => {
      pushedQ.current = text;
      void navigate({ search: (prev) => ({ ...prev, q: text || undefined }), replace: true });
    }, 250);
    return () => window.clearTimeout(t);
  }, [text, search.q, navigate]);

  // C10: `?event=<id>` opens the sheet even when the event isn't in a
  // currently loaded page. Only fetch it directly once the list itself has
  // settled and doesn't already have it, so a normal row click (the event
  // is always already in `rows`) never fires a second request.
  const rowEvent = search.event !== undefined ? rows.find((e) => e.id === search.event) : undefined;
  const needsFetch = allowed && search.event !== undefined && !rowEvent && !list.isPending;
  const eventFetch = useQuery({ ...auditEventQuery(search.event ?? 0), enabled: needsFetch });
  // A new deep link (a fresh `?event=<id>`) starts clean; the notice from a
  // previous attempt must not vanish the instant this same 404 clears its
  // own `event` param below, so this only resets on a newly *set* id.
  useEffect(() => {
    if (search.event !== undefined) setMissingNotice(false);
  }, [search.event]);
  useEffect(() => {
    if (!needsFetch || !eventFetch.isError) return;
    const err = eventFetch.error;
    if (err instanceof ApiError && err.status === 404) {
      setMissingNotice(true);
      set({ event: undefined });
    } else {
      toast.error(errorMessage(err));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [needsFetch, eventFetch.isError, eventFetch.error]);
  const sheetEvent = rowEvent ?? (needsFetch ? eventFetch.data : undefined);

  if (!allowed) {
    return (
      <>
        <PageHeader title="Audit log" />
        <EmptyState message="Your role can't read the audit log here." />
      </>
    );
  }

  const actorName = (id: string) => users.data?.find((u) => u.id === id)?.displayName ?? id;
  const chips = [
    ...(search.from ? [{ key: 'from', label: `From ${search.from}` }] : []),
    ...(search.to ? [{ key: 'to', label: `To ${search.to}` }] : []),
    ...(search.actor ? [{ key: 'actor', label: `Actor: ${actorName(search.actor)}` }] : []),
    ...(search.action ? [{ key: 'action', label: `Action: ${actionLabel(search.action)}` }] : []),
    ...(search.resourceType ? [{ key: 'resourceType', label: `Resource: ${search.resourceType}` }] : []),
    ...(search.resourceId ? [{ key: 'resourceId', label: `Resource id: ${search.resourceId}` }] : []),
    ...(search.q ? [{ key: 'q', label: `Search: ${search.q}` }] : []),
  ];

  async function exportCsv() {
    setExporting(true);
    try {
      const { truncated, incomplete } = await exportAudit(filter);
      setExportNotice(truncated);
      setExportError(incomplete);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Audit log"
        activeFilters={chips.length}
        onClearFilters={clear}
        filterChips={<FilterChips chips={chips} onRemove={(k) => set({ [k]: undefined })} onClear={clear} />}
        filtersTrailing={
          <SavedViews
            list="audit"
            current={{ from: search.from, to: search.to, actor: search.actor, action: search.action, resourceType: search.resourceType, resourceId: search.resourceId, q: search.q }}
            onApply={(s) => void navigate({ search: auditSearch.parse(s) })}
          />
        }
        filters={
          <>
            <FilterField label="Search">
              <div className="relative w-64">
                <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
                <Input aria-label="Search audit log" className="pl-8" placeholder="certificate.renew" value={text} onChange={(e) => setText(e.target.value)} />
              </div>
            </FilterField>
            <FilterField label="Action">
              <div className="w-48">
                <Combobox aria-label="Action" value={search.action} onChange={(v) => set({ action: v })} options={actionOptions()} placeholder="Any action" emptyText="No action matches." mono />
              </div>
            </FilterField>
            <FilterField label="Resource">
              <div className="w-48">
                <Combobox aria-label="Resource type" value={search.resourceType} onChange={(v) => set({ resourceType: v })} options={AUDIT_RESOURCE_TYPES.map((t) => ({ value: t, label: t }))} placeholder="Any resource" emptyText="No type matches." mono />
              </div>
            </FilterField>
            {users.data && (
              <FilterField label="Actor">
                <div className="w-48">
                  <Combobox aria-label="Actor" value={search.actor} onChange={(v) => set({ actor: v })} options={users.data.map((u) => ({ value: u.id, label: u.displayName, hint: u.email ?? undefined }))} placeholder="Any actor" emptyText="No user matches." />
                </div>
              </FilterField>
            )}
            <FilterField label="From">
              <Input aria-label="From date" className="w-40" type="date" value={search.from ?? ''} onChange={(e) => set({ from: e.target.value || undefined })} />
            </FilterField>
            <FilterField label="To">
              <Input aria-label="To date" className="w-40" type="date" value={search.to ?? ''} onChange={(e) => set({ to: e.target.value || undefined })} />
            </FilterField>
          </>
        }
        actions={
          <div className="flex flex-wrap items-center gap-3">
            {canVerifyChain && <ChainStatus />}
            {exportError && <ToneChip tone="failed" icon={TriangleAlert} label="Export incomplete" help="audit.exportError" />}
            <Button disabled={exporting} onClick={() => void exportCsv()}>
              <Download className="size-4" aria-hidden />
              Export CSV
            </Button>
          </div>
        }
      />
      {missingNotice && (
        <ToneChip className="mb-3" tone="neutral" icon={Info} label="That event doesn't exist or isn't visible to you." help="audit.missingEvent" />
      )}
      {exportNotice && (
        <ToneChip className="mb-3" tone="pending" icon={TriangleAlert} label="The export hit the 100,000-row cap" help="audit.exportTruncated" />
      )}
      {list.isError ? (
        <ErrorState message={`Couldn't load the audit log. ${errorMessage(list.error)}`} onRetry={() => void list.refetch()} />
      ) : !list.isPending && rows.length === 0 ? (
        <EmptyState message="No events match these filters.">
          {chips.length > 0 && (
            <Button variant="outline" onClick={clear}>
              Clear filters
            </Button>
          )}
        </EmptyState>
      ) : isMdUp ? (
        <DataTable ariaLabel="Audit events" data={rows} columns={columns} getRowId={(e) => String(e.id)} onRowClick={(id) => set({ event: Number(id) })} skeletonRows={list.isPending ? 5 : undefined} />
      ) : list.isPending ? (
        <div role="status" aria-label="Loading audit events" className="grid gap-2">
          <AuditCardSkeleton />
          <AuditCardSkeleton />
          <AuditCardSkeleton />
        </div>
      ) : (
        <div className="grid gap-2">
          {rows.map((e) => (
            <button key={e.id} type="button" className="text-left" onClick={() => set({ event: e.id })}>
              <AuditCard event={e} orgName={allOrgs ? orgName(e.orgId) : undefined} />
            </button>
          ))}
        </div>
      )}
      {list.hasNextPage && (
        <Button variant="outline" className="mt-3" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
          Load more
        </Button>
      )}
      <EventSheet event={sheetEvent} orgName={orgName} onClose={() => set({ event: undefined })} />
    </>
  );
}
