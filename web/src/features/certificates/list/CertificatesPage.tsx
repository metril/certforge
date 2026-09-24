import { useEffect, useMemo, useState } from 'react';
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { Plus, RotateCw, Search, Trash2 } from 'lucide-react';
import { ApiError } from '@/api/errors';
import { casQuery } from '@/api/queries/cas';
import { certificatesInfinite, certListQueryKey, useDeleteCertificates, useRenewCertificates } from '@/api/queries/certificates';
import { BulkBar } from '@/components/BulkBar';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { FilterChips } from '@/components/FilterChips';
import { PageHeader } from '@/components/PageHeader';
import { SavedViews } from '@/components/SavedViews';
import { SegmentedControl } from '@/components/SegmentedControl';
import { StatusChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { CertValidity } from '@/components/ValidityBar';
import type { Certificate } from '@/api/types';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { useOrg } from '@/lib/org';
import { useRowSelection } from '@/lib/selection';
import { STATUS_META } from '@/lib/status';
import { relDays } from '@/lib/time';
import { certColumns } from './columns';
import { certListSearch, type CertListSearch } from './search';

type StatusFilter = 'all' | 'active' | 'pending' | 'failed' | 'expired';

// Card rows below `md` (controller ruling / preflight D9: the spec calls for
// "card lists" under 768 px; a fixed-width table would scroll horizontally
// on a phone instead).
function CertCard({ cert, org }: { cert: Certificate; org: string }) {
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
      <CertValidity cert={cert} />
      <div className="flex items-center justify-between text-xs text-ink-muted">
        <span>Next renewal</span>
        <span>{cert.nextRenewAt ? relDays(cert.nextRenewAt) : '–'}</span>
      </div>
    </Link>
  );
}

export function CertificatesPage() {
  const org = useOrg();
  const qc = useQueryClient();
  const search = useSearch({ from: '/_app/o/$org/certificates/' });
  const navigate = useNavigate({ from: '/o/$org/certificates/' });
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const list = useInfiniteQuery(certificatesInfinite(org.id, search));
  const { data: cas = [] } = useQuery(casQuery(org.id));
  const renew = useRenewCertificates(org.id);
  const del = useDeleteCertificates(org.id);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [text, setText] = useState(search.q ?? '');
  const [cursorNotice, setCursorNotice] = useState(false);

  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const ids = useMemo(() => rows.map((r) => r.id), [rows]);
  const sel = useRowSelection(ids);
  const columns = useMemo(() => certColumns(org.slug, (id) => cas.find((c) => c.id === id)?.name), [org.slug, cas]);

  const setSearch = (patch: Partial<CertListSearch>) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });

  useEffect(() => {
    const t = window.setTimeout(() => {
      if ((search.q ?? '') !== text) void navigate({ search: (prev) => ({ ...prev, q: text || undefined }), replace: true });
    }, 250);
    return () => window.clearTimeout(t);
  }, [text, search.q, navigate]);

  // A saved view, a typed filter, or a sort change starts a fresh query key
  // (certificatesInfinite keys on the whole search object), which drops any
  // cursor automatically; clear a stale-cursor notice from a previous page
  // once the visible filters move on.
  useEffect(() => {
    setCursorNotice(false);
  }, [search.status, search.q, search.sort]);

  const chips = [
    ...(search.status ? [{ key: 'status', label: `Status: ${STATUS_META[search.status].label}` }] : []),
    ...(search.q ? [{ key: 'q', label: `Search: ${search.q}` }] : []),
  ];
  const clearAll = () => {
    setText('');
    void navigate({ search: {} });
  };
  const emptyUnfiltered = !list.isPending && rows.length === 0 && chips.length === 0;
  const newLink = (
    <Button asChild>
      <Link to="/o/$org/certificates/new" params={{ org: org.slug }}>
        <Plus className="size-4" aria-hidden />
        New certificate
      </Link>
    </Button>
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
      await qc.resetQueries({ queryKey: certListQueryKey(org.id, search) });
    }
  };

  return (
    <>
      <PageHeader title="Certificates" actions={emptyUnfiltered ? undefined : newLink} />
      {emptyUnfiltered ? (
        <EmptyState message="No certificates yet.">{newLink}</EmptyState>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <SegmentedControl<StatusFilter>
              aria-label="Status"
              value={search.status && search.status !== 'revoked' ? search.status : 'all'}
              onChange={(v) => setSearch({ status: v === 'all' ? undefined : v })}
              options={[
                { value: 'all', label: 'All' },
                { value: 'active', label: 'Active' },
                { value: 'pending', label: 'Pending' },
                { value: 'failed', label: 'Failed' },
                { value: 'expired', label: 'Expired' },
              ]}
            />
            <div className="relative w-72">
              <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
              <Input aria-label="Search certificates" className="pl-8 font-mono text-xs" placeholder="example.com" value={text} onChange={(e) => setText(e.target.value)} />
            </div>
            <SavedViews list="certificates" current={{ status: search.status, q: search.q, sort: search.sort }} onApply={(s) => void navigate({ search: certListSearch.parse(s) })} />
          </div>
          <FilterChips
            className="mb-3"
            chips={chips}
            onRemove={(k) => {
              if (k === 'q') setText('');
              setSearch({ [k]: undefined });
            }}
            onClear={clearAll}
          />
          {cursorNotice && <p className="mb-3 text-xs text-ink-muted">The list changed since it was loaded; showing the first page again.</p>}
          {list.isPending ? (
            <p className="text-ink-muted">Loading…</p>
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
              selected={sel.selected}
              onRowClick={sel.onRowClick}
              onRowOpen={(id) => void navigate({ to: '/o/$org/certificates/$id/$tab', params: { org: org.slug, id, tab: 'overview' } })}
            />
          ) : (
            <div className="grid gap-2">
              {rows.map((c) => (
                <CertCard key={c.id} cert={c} org={org.slug} />
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
      <BulkBar count={sel.selected.size} onClear={sel.clear}>
        <Button size="sm" disabled={renew.isPending} onClick={() => renew.mutate([...sel.selected], { onSuccess: sel.clear })}>
          <RotateCw className="size-4" aria-hidden />
          Renew
        </Button>
        <Button size="sm" variant="outline" onClick={() => setConfirmDelete(true)}>
          <Trash2 className="size-4" aria-hidden />
          Delete
        </Button>
      </BulkBar>
      <ConfirmDestructive
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`Delete ${sel.selected.size} certificates`}
        consequence="Their versions and private keys are deleted and they stop renewing."
        confirmText="delete"
        actionLabel="Delete"
        onConfirm={async () => {
          await del.mutateAsync([...sel.selected]);
          sel.clear();
        }}
      />
    </>
  );
}
