import { useEffect, useMemo, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Download, Search } from 'lucide-react';
import { toast } from 'sonner';
import type { AuditEvent } from '@/api/types';
import { errorMessage } from '@/api/errors';
import { auditEventQuery, auditInfinite, exportAudit } from '@/api/queries/audit';
import { usersQuery } from '@/api/queries/users';
import { Combobox } from '@/components/Combobox';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { Field } from '@/components/Field';
import { FilterChips } from '@/components/FilterChips';
import { PageHeader } from '@/components/PageHeader';
import { SavedViews } from '@/components/SavedViews';
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
  const filter = useMemo(() => toApiFilter(search, allOrgs ? undefined : org.id), [search, allOrgs, org.id]);
  const list = useInfiniteQuery({ ...auditInfinite(filter), enabled: allowed });
  const users = useQuery({ ...usersQuery, enabled: allowed && canAnywhere(me, 'users:read') });
  const [text, setText] = useState(search.q ?? '');
  const [exporting, setExporting] = useState(false);
  const [exportNotice, setExportNotice] = useState(false);
  const [missingNotice, setMissingNotice] = useState(false);
  useEffect(() => setText(search.q ?? ''), [search.q]);

  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const orgName = useMemo(() => (id: string | null) => (id === null ? 'Global' : (me.orgs.find((o) => o.id === id)?.name ?? id)), [me.orgs]);
  const columns = useMemo(() => auditColumns(allOrgs ? orgName : undefined), [allOrgs, orgName]);
  const set = (patch: Partial<AuditSearch>) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });
  const clear = () => void navigate({ search: {} });

  // C10: `?event=<id>` opens the sheet even when the event isn't in a
  // currently loaded page. Only fetch it directly once the list itself has
  // settled and doesn't already have it, so a normal row click (the event
  // is always already in `rows`) never fires a second request.
  const rowEvent = search.event !== undefined ? rows.find((e) => e.id === search.event) : undefined;
  const needsFetch = allowed && search.event !== undefined && !rowEvent && !list.isPending;
  const eventFetch = useQuery({ ...auditEventQuery(search.event ?? 0), enabled: needsFetch });
  useEffect(() => {
    if (needsFetch && eventFetch.isError) {
      setMissingNotice(true);
      set({ event: undefined });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [needsFetch, eventFetch.isError]);
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
      const truncated = await exportAudit(filter);
      setExportNotice(truncated);
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
        actions={
          <div className="flex flex-wrap items-center gap-3">
            <ChainStatus />
            <Button disabled={exporting} onClick={() => void exportCsv()}>
              <Download className="size-4" aria-hidden />
              Export CSV
            </Button>
          </div>
        }
      />
      {missingNotice && <p className="mb-3 text-xs text-ink-muted">That event doesn't exist or isn't visible to you.</p>}
      {exportNotice && <p className="mb-3 text-xs text-ink-muted">The export hit the 100,000-row cap; some events aren't included.</p>}
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <form
          className="relative w-64"
          onSubmit={(e) => {
            e.preventDefault();
            set({ q: text.trim() || undefined });
          }}
        >
          <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
          <Input aria-label="Search audit log" className="pl-8" placeholder="www.example.com" value={text} onChange={(e) => setText(e.target.value)} onBlur={() => set({ q: text.trim() || undefined })} />
        </form>
        <div className="w-56">
          <Combobox aria-label="Action" value={search.action} onChange={(v) => set({ action: v })} options={actionOptions()} placeholder="Any action" emptyText="No action matches." mono />
        </div>
        <div className="w-48">
          <Combobox aria-label="Resource type" value={search.resourceType} onChange={(v) => set({ resourceType: v })} options={AUDIT_RESOURCE_TYPES.map((t) => ({ value: t, label: t }))} placeholder="Any resource" emptyText="No type matches." mono />
        </div>
        {users.data && (
          <div className="w-48">
            <Combobox aria-label="Actor" value={search.actor} onChange={(v) => set({ actor: v })} options={users.data.map((u) => ({ value: u.id, label: u.displayName, hint: u.email ?? undefined }))} placeholder="Any actor" emptyText="No user matches." />
          </div>
        )}
        <Field id="audit-from" label="From" className="w-40">
          <Input id="audit-from" type="date" value={search.from ?? ''} onChange={(e) => set({ from: e.target.value || undefined })} />
        </Field>
        <Field id="audit-to" label="To" className="w-40">
          <Input id="audit-to" type="date" value={search.to ?? ''} onChange={(e) => set({ to: e.target.value || undefined })} />
        </Field>
        <SavedViews
          list="audit"
          current={{ from: search.from, to: search.to, actor: search.actor, action: search.action, resourceType: search.resourceType, resourceId: search.resourceId, q: search.q }}
          onApply={(s) => void navigate({ search: auditSearch.parse(s) })}
        />
      </div>
      <FilterChips className="mb-3" chips={chips} onRemove={(k) => set({ [k]: undefined })} onClear={clear} />
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
