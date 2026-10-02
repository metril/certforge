import { useCallback, useEffect, useMemo, useState } from 'react';
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { Plus, Search } from 'lucide-react';
import { ApiError, errorMessage } from '@/api/errors';
import { allOrgsClientsInfinite, clientListKey, clientsInfinite } from '@/api/queries/clients';
import { sitesQuery } from '@/api/queries/sites';
import type { Client, ClientStatus } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { ConnectionDot } from '@/components/ConnectionDot';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { FilterChips } from '@/components/FilterChips';
import { PageHeader } from '@/components/PageHeader';
import { PermissionTip } from '@/components/PermissionTip';
import { SavedViews } from '@/components/SavedViews';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useAllOrgs, useMe, useOrg, useOrgSlugOf } from '@/lib/org';
import { can } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { useUrlText } from '@/lib/useUrlText';
import { clientColumns, clientMeta } from './columns';
import { CLIENT_STATUS_LABEL, clientListSearch, type ClientListSearch } from './search';

type StatusFilter = 'all' | ClientStatus;
const STATUS_OPTIONS: { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'pending', label: 'Pending' },
  { value: 'revoked', label: 'Revoked' },
];

function ClientCard({ client, org, context }: { client: Client; org: string; context?: string }) {
  return (
    <Link to="/o/$org/clients/$id" params={{ org, id: client.id }} className="grid gap-2 rounded-md border border-border bg-panel p-3 hover:bg-subtle">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-semibold">{client.name}</span>
        <ConnectionDot client={client} />
      </div>
      <span className="truncate text-xs text-ink-muted">{[context, ...clientMeta(client)].filter(Boolean).join(' · ')}</span>
      <span className="text-xs text-ink-muted">{client.lastSeen ? `Seen ${relTime(client.lastSeen)}` : 'Never seen'}</span>
    </Link>
  );
}

function CardSkeleton() {
  return (
    <div className="grid gap-2 rounded-md border border-border bg-panel p-3" aria-hidden>
      <div className="flex items-center justify-between gap-2">
        <div className="h-4 w-24 animate-pulse rounded-sm bg-subtle" />
        <div className="h-4 w-16 animate-pulse rounded-sm bg-subtle" />
      </div>
      <div className="h-3 w-32 animate-pulse rounded-sm bg-subtle" />
    </div>
  );
}

export function ClientsPage() {
  const org = useOrg();
  const allOrgs = useAllOrgs();
  const me = useMe();
  const qc = useQueryClient();
  const search = useSearch({ from: '/_app/o/$org/clients/' });
  const navigate = useNavigate({ from: '/o/$org/clients/' });
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const query = { status: search.status, site: allOrgs ? undefined : search.site, q: search.q, sort: search.sort };
  const list = useInfiniteQuery(allOrgs ? allOrgsClientsInfinite(query) : clientsInfinite(org.id, query));
  const { data: sites = [] } = useQuery({ ...sitesQuery(org.id), enabled: !allOrgs });
  const [cursorNotice, setCursorNotice] = useState(false);
  const setSearch = (patch: Partial<ClientListSearch>) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });
  const [text, setText] = useUrlText(search.q, (q) => setSearch({ q }));

  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const siteName = useMemo(() => {
    const byId = new Map(sites.map((s) => [s.id, s.name]));
    return (id: string | null) => (id ? (byId.get(id) ?? '–') : '–');
  }, [sites]);
  const orgName = useMemo(() => (c: Client) => me.orgs.find((o) => o.id === c.orgId)?.name ?? c.orgId, [me.orgs]);
  const slugOf = useOrgSlugOf();
  const slug = useCallback((c: Client) => (allOrgs ? slugOf(c.orgId) : org.slug), [allOrgs, slugOf, org.slug]);
  const columns = useMemo(
    () => (allOrgs ? clientColumns({ slugOf: slug, orgName }) : clientColumns({ slugOf: slug, siteName })),
    [allOrgs, orgName, siteName, slug],
  );

  useEffect(() => setCursorNotice(false), [search.status, search.site, search.q, search.sort, allOrgs]);

  // A background refetch (the list polls) can also hit a stale cursor, not
  // only a Load more click: show the same notice and reset either way, and
  // keep whatever rows are already on screen rather than replacing them
  // with an error state.
  useEffect(() => {
    if (list.error instanceof ApiError && list.error.status === 422) {
      setCursorNotice(true);
      void qc.resetQueries({ queryKey: clientListKey(allOrgs ? 'all' : org.id, query) });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.error]);

  const chips = [
    ...(search.status ? [{ key: 'status', label: `Status: ${CLIENT_STATUS_LABEL[search.status]}` }] : []),
    ...(search.site && !allOrgs ? [{ key: 'site', label: `Site: ${sites.find((s) => s.id === search.site)?.name ?? search.site}` }] : []),
    ...(search.q ? [{ key: 'q', label: `Search: ${search.q}` }] : []),
  ];
  const clearAll = () => void navigate({ search: {} });
  const emptyUnfiltered = !list.isPending && !list.isError && rows.length === 0 && chips.length === 0;
  const canWrite = !allOrgs && can(me, 'clients:write', org.id);
  const enrol = canWrite ? (
    <Button asChild>
      <Link to="/o/$org/clients/new" params={{ org: org.slug }}>
        <Plus className="size-4" aria-hidden />
        Enrol client
      </Link>
    </Button>
  ) : (
    <PermissionTip allowed={false} action="clients:write">
      <Button disabled>
        <Plus className="size-4" aria-hidden />
        Enrol client
      </Button>
    </PermissionTip>
  );

  // A cursor is bound to its filters and can go stale (422): reset to page one.
  const loadMore = async () => {
    const res = await list.fetchNextPage();
    if (res.error instanceof ApiError && res.error.status === 422) {
      setCursorNotice(true);
      await qc.resetQueries({ queryKey: clientListKey(allOrgs ? 'all' : org.id, query) });
    }
  };

  return (
    <>
      <PageHeader
        title="Clients"
        help="client.connection"
        actions={emptyUnfiltered || allOrgs ? undefined : enrol}
        activeFilters={chips.length}
        filters={
          emptyUnfiltered ? undefined : (
            <>
              <SegmentedControl<StatusFilter>
                aria-label="Status"
                value={search.status ?? 'all'}
                onChange={(v) => setSearch({ status: v === 'all' ? undefined : v })}
                options={STATUS_OPTIONS}
              />
              {!allOrgs && sites.length > 0 && (
                <div className="w-full md:w-40">
                  <Combobox
                    aria-label="Site"
                    value={search.site}
                    onChange={(v) => setSearch({ site: v })}
                    options={sites.map((s) => ({ value: s.id, label: s.name }))}
                    placeholder="All sites"
                    emptyText="No site matches."
                  />
                </div>
              )}
              <div className="relative w-full md:w-52">
                <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
                <Input aria-label="Search clients" className="pl-8 font-mono text-xs" placeholder="web-1" maxLength={200} value={text} onChange={(e) => setText(e.target.value)} />
              </div>
              <SavedViews
                list="clients"
                current={{ status: search.status, site: allOrgs ? undefined : search.site, q: search.q, sort: search.sort }}
                onApply={(s) => void navigate({ search: clientListSearch.parse(s) })}
              />
            </>
          )
        }
      />
      {emptyUnfiltered ? (
        <EmptyState message="No clients yet.">{!allOrgs && enrol}</EmptyState>
      ) : (
        <>
          <FilterChips className="mb-3" chips={chips} onRemove={(k) => setSearch({ [k]: undefined })} onClear={clearAll} />
          {cursorNotice && <p className="mb-3 text-xs text-ink-muted">The list changed since it was loaded; showing the first page again.</p>}
          {list.isError && rows.length === 0 ? (
            <ErrorState message={`Couldn't load clients. ${errorMessage(list.error)}`} onRetry={() => void list.refetch()} />
          ) : list.isPending ? (
            isMdUp ? (
              <DataTable ariaLabel="Clients" data={[]} columns={columns} getRowId={(r) => r.id} skeletonRows={3} />
            ) : (
              <div role="status" aria-label="Loading clients" className="grid gap-2">
                <CardSkeleton />
                <CardSkeleton />
                <CardSkeleton />
              </div>
            )
          ) : rows.length === 0 ? (
            <EmptyState message="No clients match these filters.">
              <Button variant="outline" onClick={clearAll}>
                Clear filters
              </Button>
            </EmptyState>
          ) : isMdUp ? (
            <DataTable
              ariaLabel="Clients"
              data={rows}
              columns={columns}
              getRowId={(r) => r.id}
              sort={search.sort}
              onSort={(s) => setSearch({ sort: s as ClientListSearch['sort'] })}
              onRowOpen={(id) => {
                const c = rows.find((r) => r.id === id);
                if (c) void navigate({ to: '/o/$org/clients/$id', params: { org: slug(c), id } });
              }}
            />
          ) : (
            <div className="grid gap-2">
              {rows.map((c) => (
                <ClientCard key={c.id} client={c} org={slug(c)} context={allOrgs ? orgName(c) : c.siteId ? siteName(c.siteId) : undefined} />
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
    </>
  );
}
