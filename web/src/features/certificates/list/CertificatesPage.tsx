import { useEffect, useMemo, useRef, useState } from 'react';
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { Plus, RotateCw, Search, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { casQuery } from '@/api/queries/cas';
import {
  allOrgsCertificatesInfinite,
  allOrgsCertificatesListKey,
  BulkActionError,
  certificatesInfinite,
  certListQueryKey,
  plural,
  useDeleteCertificates,
  useRenewCertificates,
  type BulkResult,
} from '@/api/queries/certificates';
import { BulkBar } from '@/components/BulkBar';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { FilterField } from '@/components/FilterToolbar';
import { FilterChips } from '@/components/FilterChips';
import { PageHeader } from '@/components/PageHeader';
import { PermissionTip } from '@/components/PermissionTip';
import { SavedViews } from '@/components/SavedViews';
import { SegmentedControl } from '@/components/SegmentedControl';
import { StatusChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { CertValidity } from '@/components/ValidityBar';
import type { Certificate } from '@/api/types';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { useAllOrgs, useMe, useOrg, useOrgSlugOf } from '@/lib/org';
import { can } from '@/lib/permissions';
import { useRowSelection } from '@/lib/selection';
import { STATUS_META } from '@/lib/status';
import { relDays } from '@/lib/time';
import { certColumns, certMeta } from './columns';
import { ImportMenu } from './ImportMenu';
import { certListSearch, type CertListSearch } from './search';

type StatusFilter = 'all' | 'active' | 'pending' | 'failed' | 'expired' | 'revoked';

const STATUS_OPTIONS: { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'pending', label: 'Pending' },
  { value: 'failed', label: 'Failed' },
  { value: 'expired', label: 'Expired' },
  // Fix round 1 (review): the segmented control silently fell back to "All"
  // for status=revoked, even though the filter chip above it correctly said
  // "Status: Revoked" — a visible mismatch. Revoked gets its own segment,
  // matching every other real status.
  { value: 'revoked', label: 'Revoked' },
];

// Up to 5 names in a bulk-failure toast (review fix round 1); ids beyond
// that collapse into a "+N more" suffix instead of an unbounded list.
function bulkFailureMessage(ids: string[], nameOf: (id: string) => string): string {
  const shown = ids.slice(0, 5).map(nameOf);
  const rest = ids.length - shown.length;
  return `${plural(ids.length, 'certificate')} failed: ${shown.join(', ')}${rest > 0 ? `, +${rest} more` : ''}`;
}

// Card rows below `md` (controller ruling / preflight D9: the spec calls for
// "card lists" under 768 px; a fixed-width table would scroll horizontally
// on a phone instead).
function CertCard({ cert, org, orgName, ca }: { cert: Certificate; org: string; orgName?: string; ca?: string }) {
  return (
    <Link
      to="/o/$org/certificates/$id/$tab"
      params={{ org, id: cert.id, tab: 'overview' }}
      className="grid gap-2 rounded-md border border-border bg-panel p-3"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-semibold">{cert.name}</span>
        <StatusChip status={cert.status} />
      </div>
      <span className="truncate text-xs text-ink-muted">{[orgName, ...certMeta(cert, ca)].filter(Boolean).join(' · ')}</span>
      <CertValidity cert={cert} />
      <div className="flex items-center justify-between text-xs text-ink-muted">
        <span>Next renewal</span>
        <span>{cert.nextRenewAt ? relDays(cert.nextRenewAt) : '–'}</span>
      </div>
    </Link>
  );
}

function CertCardSkeleton() {
  return (
    <div className="grid gap-2 rounded-md border border-border bg-panel p-3" aria-hidden>
      <div className="flex items-center justify-between gap-2">
        <div className="h-4 w-24 animate-pulse rounded-sm bg-subtle" />
        <div className="h-6 w-16 animate-pulse rounded-sm bg-subtle" />
      </div>
      <div className="h-1.5 w-full animate-pulse rounded-sm bg-subtle" />
      <div className="flex items-center justify-between">
        <div className="h-3 w-20 animate-pulse rounded-sm bg-subtle" />
        <div className="h-3 w-12 animate-pulse rounded-sm bg-subtle" />
      </div>
    </div>
  );
}

export function CertificatesPage() {
  const org = useOrg();
  const allOrgs = useAllOrgs();
  const slugOf = useOrgSlugOf();
  const me = useMe();
  const qc = useQueryClient();
  const search = useSearch({ from: '/_app/o/$org/certificates/' });
  const navigate = useNavigate({ from: '/o/$org/certificates/' });
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const list = useInfiniteQuery(allOrgs ? allOrgsCertificatesInfinite(search) : certificatesInfinite(org.id, search));
  const { data: cas = [] } = useQuery({ ...casQuery(org.id), enabled: !allOrgs });
  const renew = useRenewCertificates(org.id);
  const del = useDeleteCertificates(org.id);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [text, setText] = useState(search.q ?? '');
  const [cursorNotice, setCursorNotice] = useState(false);

  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const ids = useMemo(() => rows.map((r) => r.id), [rows]);
  const sel = useRowSelection(ids);
  // Falls back to the raw org id (not '–') when a cert's org isn't in
  // `me.orgs` — an unresolvable name should still be visibly the org id,
  // not silently blank (fix round 1).
  const orgNameOf = useMemo(
    () => (c: Certificate) => me.orgs.find((o) => o.id === c.orgId)?.name ?? c.orgId ?? '–',
    [me.orgs],
  );
  const columns = useMemo(
    () =>
      allOrgs
        ? certColumns((c) => slugOf(c.orgId), () => undefined, orgNameOf)
        : certColumns(org.slug, (id) => cas.find((c) => c.id === id)?.name),
    [allOrgs, org.slug, cas, orgNameOf, slugOf],
  );
  const nameOf = useMemo(() => {
    const byId = new Map(rows.map((r) => [r.id, r.name]));
    return (id: string) => byId.get(id) ?? id;
  }, [rows]);

  const setSearch = (patch: Partial<CertListSearch>) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });

  // Fix round 1 (review, Important): this used to read `search.q` only at
  // mount, so applying a saved view, browser back/forward, or a filter chip
  // removal set the URL's `q` correctly but left `text` — and therefore the
  // debounce below — holding the old typed value, which 250ms later
  // navigated right back over the external change. `pushedQ` tracks the
  // last `q` *this* effect itself pushed to the URL: when the URL's `q`
  // differs from that, it's an external change, so sync `text` from it and
  // skip scheduling a navigate entirely (both branches live in one effect
  // so an external change is detected before any stale `text` can trigger a
  // debounce on the very same render).
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

  // A saved view, a typed filter, or a sort change starts a fresh query key
  // (certificatesInfinite keys on the whole search object), which drops any
  // cursor automatically; clear a stale-cursor notice from a previous page,
  // and (review fix round 1) explicitly drop row selection too, instead of
  // relying on `useRowSelection`'s own "still in the new result set" prune,
  // which could coincidentally keep a row selected that just happens to
  // reappear in the newly filtered page.
  useEffect(() => {
    setCursorNotice(false);
    sel.clear();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search.status, search.q, search.sort, allOrgs, sel.clear]);

  const chips = [
    ...(search.status ? [{ key: 'status', label: `Status: ${STATUS_META[search.status].label}` }] : []),
    ...(search.q ? [{ key: 'q', label: `Search: ${search.q}` }] : []),
  ];
  const clearAll = () => void navigate({ search: {} });
  const emptyUnfiltered = !list.isPending && !list.isError && rows.length === 0 && chips.length === 0;
  const canCreate = can(me, 'certs:write', org.id);
  const canIssue = can(me, 'certs:issue', org.id);
  const canDelete = can(me, 'certs:write', org.id);
  const newLink = canCreate ? (
    <Button asChild>
      <Link to="/o/$org/certificates/new" params={{ org: org.slug }}>
        <Plus className="size-4" aria-hidden />
        New certificate
      </Link>
    </Button>
  ) : (
    <PermissionTip allowed={false} action="certs:write">
      <Button disabled>
        <Plus className="size-4" aria-hidden />
        New certificate
      </Button>
    </PermissionTip>
  );

  // Adaptation (controller ruling, not covered by a literal test in the
  // brief): a cursor bound to the current status/q/sort combination can go
  // stale (for example a bulk delete invalidates the list while a second
  // page's cursor still points at a since-removed row) and the API answers
  // 422. Reset silently to the first page and leave a one-line notice
  // instead of surfacing the raw error.
  const loadMore = async () => {
    const res = await list.fetchNextPage();
    if (res.error instanceof ApiError && res.error.status === 422) {
      setCursorNotice(true);
      await qc.resetQueries({ queryKey: allOrgs ? allOrgsCertificatesListKey(search) : certListQueryKey(org.id, search) });
    }
  };

  // Fix round 1 (review, Important): both bulk actions used to clear the
  // whole selection and report only counts, even when every id failed —
  // for delete that also meant the confirm dialog closed as if nothing had
  // gone wrong. `settleBulk` (in the query hooks) now throws
  // `BulkActionError` on a total failure and returns the failed ids
  // otherwise, so this handler can keep exactly those rows selected and
  // name them (the hooks only have ids; this page has `rows` to name them
  // with).
  const reportBulk = ({ ok, failed }: BulkResult, verb: string) => {
    if (ok.length > 0) toast.success(`${verb} ${plural(ok.length, 'certificate')}`);
    if (failed.length > 0) {
      toast.error(bulkFailureMessage(failed, nameOf));
      sel.replace(failed);
    }
  };

  // Import (C1): unlike New certificate, which moves into the empty state's
  // own body, Import stays in the header even when the list is empty and
  // unfiltered, so an org with no certificates yet can still reach it. Both
  // are absent entirely under All orgs.
  const headerActions = allOrgs ? undefined : (
    <>
      {!emptyUnfiltered && newLink}
      <ImportMenu orgSlug={org.slug} canWrite={canCreate} />
    </>
  );

  return (
    <>
      <PageHeader
        title="Certificates"
        help="status.column"
        actions={headerActions}
        activeFilters={chips.length}
        onClearFilters={clearAll}
        filterChips={<FilterChips chips={chips} onRemove={(k) => setSearch({ [k]: undefined })} onClear={clearAll} />}
        filtersTrailing={emptyUnfiltered ? undefined : <SavedViews list="certificates" current={{ status: search.status, q: search.q, sort: search.sort }} onApply={(s) => void navigate({ search: certListSearch.parse(s) })} />}
        filters={
          emptyUnfiltered ? undefined : (
            <>
              <FilterField label="Status">
                <SegmentedControl<StatusFilter>
                  aria-label="Status"
                  value={search.status ?? 'all'}
                  onChange={(v) => setSearch({ status: v === 'all' ? undefined : v })}
                  options={STATUS_OPTIONS}
                />
              </FilterField>
              <FilterField label="Search">
                <div className="relative w-full md:w-60">
                  <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
                  <Input aria-label="Search certificates" className="pl-8 font-mono text-xs" placeholder="example.com" value={text} onChange={(e) => setText(e.target.value)} />
                </div>
              </FilterField>
            </>
          )
        }
      />
      {emptyUnfiltered ? (
        <EmptyState message="No certificates yet.">{!allOrgs && newLink}</EmptyState>
      ) : (
        <>
          {cursorNotice && <p className="mb-3 text-xs text-ink-muted">The list changed since it was loaded; showing the first page again.</p>}
          {list.isError && rows.length === 0 ? (
            <ErrorState message={`Couldn't load certificates. ${errorMessage(list.error)}`} onRetry={() => void list.refetch()} />
          ) : list.isPending ? (
            isMdUp ? (
              <DataTable ariaLabel="Certificates" data={[]} columns={columns} getRowId={(r) => r.id} skeletonRows={3} />
            ) : (
              <div role="status" aria-label="Loading certificates" className="grid gap-2">
                <CertCardSkeleton />
                <CertCardSkeleton />
                <CertCardSkeleton />
              </div>
            )
          ) : rows.length === 0 ? (
            <EmptyState message="No certificates match these filters.">
              <Button variant="outline" onClick={clearAll}>Clear filters</Button>
            </EmptyState>
          ) : isMdUp ? (
            <DataTable
              ariaLabel="Certificates"
              data={rows}
              columns={columns}
              getRowId={(r) => r.id}
              sort={search.sort}
              onSort={(s) => setSearch({ sort: s as CertListSearch['sort'] })}
              selected={allOrgs ? undefined : sel.selected}
              onRowClick={allOrgs ? undefined : sel.onRowClick}
              onRowOpen={(id) => {
                const c = rows.find((r) => r.id === id);
                void navigate({
                  to: '/o/$org/certificates/$id/$tab',
                  params: { org: allOrgs ? slugOf(c?.orgId) : org.slug, id, tab: 'overview' },
                });
              }}
            />
          ) : (
            <div className="grid gap-2">
              {rows.map((c) => (
                <CertCard key={c.id} cert={c} ca={cas.find((x) => x.id === c.effective?.caId?.value)?.name} org={allOrgs ? slugOf(c.orgId) : org.slug} orgName={allOrgs ? orgNameOf(c) : undefined} />
              ))}
            </div>
          )}
          {list.hasNextPage && (
            <Button variant="outline" className="mt-3" disabled={list.isFetchingNextPage} onClick={() => void loadMore()}>
              Load more
            </Button>
          )}
        </>
      )}
      {isMdUp && !allOrgs && (
        <BulkBar count={sel.selected.size} onClear={sel.clear}>
          <PermissionTip allowed={canIssue} action="certs:issue">
            <Button
              size="sm"
              disabled={renew.isPending || !canIssue}
              onClick={() => {
                const targets = [...sel.selected];
                renew.mutate(targets, {
                  onSuccess: (r) => reportBulk(r, 'Renewal queued for'),
                  onError: (err) => {
                    if (err instanceof BulkActionError) {
                      toast.error(bulkFailureMessage(err.failed, nameOf));
                      sel.replace(err.failed);
                    }
                  },
                });
              }}
            >
              <RotateCw className="size-4" aria-hidden />
              Renew
            </Button>
          </PermissionTip>
          <PermissionTip allowed={canDelete} action="certs:write">
            <Button size="sm" variant="outline" disabled={!canDelete} onClick={() => setConfirmDelete(true)}>
              <Trash2 className="size-4" aria-hidden />
              Delete
            </Button>
          </PermissionTip>
        </BulkBar>
      )}
      <ConfirmDestructive
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`Delete ${plural(sel.selected.size, 'certificate')}`}
        consequence="Their versions and private keys are deleted and they stop renewing."
        confirmText="delete"
        actionLabel="Delete"
        onConfirm={async () => {
          const targets = [...sel.selected];
          try {
            const result = await del.mutateAsync(targets);
            reportBulk(result, 'Deleted');
            if (result.failed.length === 0) sel.clear();
          } catch (err) {
            if (err instanceof BulkActionError) {
              toast.error(bulkFailureMessage(err.failed, nameOf));
              sel.replace(err.failed);
            }
            // Re-thrown so ConfirmDestructive's own catch shows the inline
            // error and keeps the dialog open (review fix round 1) instead
            // of closing as if the delete had gone through.
            throw err;
          }
        }}
      />
    </>
  );
}
