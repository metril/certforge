import { useMemo } from 'react';
import { Globe } from 'lucide-react';
import { createColumnHelper } from '@tanstack/react-table';
import { useInfiniteQuery } from '@tanstack/react-query';
import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { eventsQuery } from '@/api/queries/events';
import { errorMessage } from '@/api/errors';
import type { EventKind, NotifyEvent } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { FilterChips } from '@/components/FilterChips';
import { FilterField } from '@/components/FilterToolbar';
import { MultiCombobox } from '@/components/MultiCombobox';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { KIND_GROUPS, KIND_LABEL, SEVERITY_META } from '@/lib/events';
import { useOrg } from '@/lib/org';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { DAY, fmtDateTime, relTime } from '@/lib/time';
import { AlertsHeader } from './AlertsLayout';
import { DeliverySummary } from './DeliveryChip';
import { EventRow, ResourceLink } from './EventRow';

type Range = '24h' | '7d' | '30d';
const RANGE_DAYS: Record<Range, number> = { '24h': 1, '7d': 7, '30d': 30 };
const RANGE_LABEL: Record<Range | 'all', string> = { all: 'All time', '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days' };
const SEVERITY_LABEL = { any: 'Any', warning: 'Warning and above', critical: 'Critical' } as const;

const KIND_OPTIONS = KIND_GROUPS.flatMap((g) => g.kinds.map((k) => ({ value: k, label: KIND_LABEL[k], group: g.label })));
const ALL_KINDS = KIND_OPTIONS.map((o) => o.value as EventKind);

/** "All kinds" when empty, the label for one, "N kinds" otherwise. */
const kindSummary = (kinds: readonly string[]) => (kinds.length === 0 ? 'All kinds' : kinds.length === 1 ? KIND_LABEL[kinds[0] as EventKind] : `${kinds.length} kinds`);

const col = createColumnHelper<NotifyEvent>();

function columns(org: string) {
  return [
    col.display({
      id: 'time',
      header: 'Time',
      meta: { className: 'w-20' },
      cell: ({ row }) => (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="block truncate text-ink-muted">{relTime(row.original.at)}</span>
          </TooltipTrigger>
          <TooltipContent>{fmtDateTime(row.original.at)}</TooltipContent>
        </Tooltip>
      ),
    }),
    col.display({
      id: 'severity',
      header: 'Severity',
      meta: { className: 'w-28' },
      cell: ({ row }) => {
        const sev = SEVERITY_META[row.original.severity];
        return <ToneChip tone={sev.tone} icon={sev.icon} label={sev.label} />;
      },
    }),
    col.display({ id: 'kind', header: 'Kind', meta: { className: 'w-40' }, cell: ({ row }) => <span className="block truncate font-medium">{KIND_LABEL[row.original.kind]}</span> }),
    col.display({
      id: 'resource',
      header: 'Resource',
      meta: { className: 'w-36' },
      cell: ({ row }) => (
        <div className="flex min-w-0 items-center gap-2">
          <ResourceLink event={row.original} org={org} className="block min-w-0 truncate font-medium hover:underline" />
          {row.original.orgId === null && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span tabIndex={0} aria-label="Global event" className="inline-flex shrink-0 rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring">
                  <Globe className="size-4 text-ink-muted" aria-hidden />
                </span>
              </TooltipTrigger>
              <TooltipContent>Global event</TooltipContent>
            </Tooltip>
          )}
        </div>
      ),
    }),
    col.display({
      id: 'summary',
      header: 'Summary',
      cell: ({ row }) => (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="block max-w-full truncate">{row.original.summary}</span>
          </TooltipTrigger>
          <TooltipContent className="max-w-md">{row.original.summary}</TooltipContent>
        </Tooltip>
      ),
    }),
    col.display({
      id: 'deliveries',
      header: 'Deliveries',
      meta: { className: 'w-36' },
      cell: ({ row }) => <DeliverySummary deliveries={row.original.deliveries} />,
    }),
  ];
}

export function EventsPage() {
  const org = useOrg();
  const { kind, severity, range } = useSearch({ from: '/_app/o/$org/alerts/events' });
  const navigate = useNavigate({ from: '/o/$org/alerts/events' });
  const wide = useMediaQuery('(min-width: 1024px)');
  // Recomputed only when the window changes, so the query key stays stable
  // between renders (a moving `since` would refetch forever).
  const since = useMemo(() => (range ? new Date(Math.floor((Date.now() - RANGE_DAYS[range] * DAY) / 60_000) * 60_000).toISOString() : undefined), [range]);
  const list = useInfiniteQuery(eventsQuery(org.id, { kind, severity, since }));
  const events = list.data?.pages.flatMap((p) => p.items) ?? [];
  const cols = useMemo(() => columns(org.slug), [org.slug]);

  const set = (patch: { kind?: EventKind[]; severity?: 'warning' | 'critical'; range?: Range }) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });
  const clear = () => void navigate({ search: {} });

  const kinds = kind ?? [];
  const activeFilters = (kinds.length > 0 ? 1 : 0) + (severity ? 1 : 0) + (range ? 1 : 0);
  const chips = [
    ...(kinds.length > 0 ? [{ key: 'kind', label: kindSummary(kinds) }] : []),
    ...(severity ? [{ key: 'severity', label: severity === 'critical' ? 'Critical' : 'Warning+' }] : []),
    ...(range ? [{ key: 'range', label: RANGE_LABEL[range] }] : []),
  ];
  const removeChip = (key: string) => set(key === 'kind' ? { kind: undefined } : key === 'severity' ? { severity: undefined } : { range: undefined });

  const empty = !list.isPending && events.length === 0;
  const header = (
    <AlertsHeader
      help="alerts.events"
      activeFilters={activeFilters}
      onClearFilters={clear}
      filterChips={<FilterChips chips={chips} onRemove={removeChip} onClear={clear} />}
      filters={
        <>
          <FilterField label="Kind">
            <div className="w-44">
              <MultiCombobox
                aria-label="Kind"
                value={kinds}
                onChange={(v) => set({ kind: v.length > 0 ? ALL_KINDS.filter((k) => v.includes(k)) : undefined })}
                options={KIND_OPTIONS}
                placeholder="All kinds"
                emptyText="No kind matches."
                triggerLabel={kindSummary}
                hideChips
              />
            </div>
          </FilterField>
          <FilterField label="Severity" help="event.severity">
            <div className="w-44">
              <Combobox
                aria-label="Severity"
                clearable={false}
                value={severity ?? 'any'}
                onChange={(v) => set({ severity: v === 'warning' || v === 'critical' ? v : undefined })}
                options={(Object.keys(SEVERITY_LABEL) as (keyof typeof SEVERITY_LABEL)[]).map((v) => ({ value: v, label: SEVERITY_LABEL[v] }))}
                placeholder="Any"
                emptyText="No match."
              />
            </div>
          </FilterField>
          <FilterField label="Time">
            <div className="w-44">
              <Combobox
                aria-label="Time"
                clearable={false}
                value={range ?? 'all'}
                onChange={(v) => set({ range: v === '24h' || v === '7d' || v === '30d' ? v : undefined })}
                options={(Object.keys(RANGE_LABEL) as (keyof typeof RANGE_LABEL)[]).map((v) => ({ value: v, label: RANGE_LABEL[v] }))}
                placeholder="All time"
                emptyText="No match."
              />
            </div>
          </FilterField>
        </>
      }
    />
  );

  if (list.isError) {
    return (
      <>
        {header}
        <ErrorState message={`Couldn't load events. ${errorMessage(list.error)}`} onRetry={() => void list.refetch()} />
      </>
    );
  }

  let body;
  if (empty) {
    body =
      activeFilters > 0 ? (
        <EmptyState message="No events match these filters.">
          <Button variant="outline" onClick={clear}>
            Clear filters
          </Button>
        </EmptyState>
      ) : (
        <EmptyState message="No events yet.">
          <Button asChild>
            <Link to="/o/$org/alerts/channels" params={{ org: org.slug }} search={{ edit: 'new' }}>
              Add channel
            </Link>
          </Button>
        </EmptyState>
      );
  } else if (wide) {
    body = <DataTable data={events} columns={cols} getRowId={(e) => e.id} ariaLabel="Events" skeletonRows={list.isPending ? 3 : undefined} />;
  } else {
    body = (
      <div role="list" aria-label="Events" className="rounded-md border border-border bg-panel px-4 [&>*:last-child]:border-b-0">
        {list.isPending
          ? [0, 1, 2].map((i) => <div key={i} aria-hidden className="h-16 animate-pulse border-b border-border bg-subtle/40" />)
          : events.map((e) => <EventRow key={e.id} event={e} org={org.slug} />)}
      </div>
    );
  }

  return (
    <>
      {header}
      <div className="grid gap-4">
        {body}
        {list.hasNextPage && (
          <Button variant="outline" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            Load more
          </Button>
        )}
      </div>
    </>
  );
}
