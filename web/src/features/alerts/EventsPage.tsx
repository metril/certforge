import { Card } from '@/components/Card';
import { useInfiniteQuery } from '@tanstack/react-query';
import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { eventsQuery } from '@/api/queries/events';
import { errorMessage } from '@/api/errors';
import type { EventKind, Severity } from '@/api/types';
import { ChipSet } from '@/components/ChipSet';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { FilterChips } from '@/components/FilterChips';
import { HelpTip } from '@/components/HelpTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { KIND_GROUPS, KIND_LABEL } from '@/lib/events';
import { useOrg } from '@/lib/org';
import { AlertsHeader } from './AlertsLayout';
import { EventRow } from './EventRow';

type SeverityFilter = 'all' | 'warning' | 'critical';

/** Every kind, in enum order (Shared contracts "Enums"), used to keep the
 * `kind` param deterministic regardless of click order across groups. */
const ALL_KINDS = KIND_GROUPS.flatMap((g) => g.kinds);

/** A group is "selected" only when every one of its kinds is present in the
 * URL (Deviations: the severity/kind chips convention "a group chip is
 * filled when all its kinds are in ?kind"). A hand-edited URL with a
 * partial group (e.g. one cert.* kind) leaves the group chip unfilled. */
function selectedGroups(kind: EventKind[] | undefined): string[] {
  const k = kind ?? [];
  return KIND_GROUPS.filter((g) => g.kinds.every((kk) => k.includes(kk))).map((g) => g.label);
}

/** Adds/removes only the groups whose selected-state actually changed
 * (batch 2 review): recomputing the whole `kind` array from `nextLabels`
 * alone would silently drop any leftover kind that isn't part of a full
 * group — e.g. a hand-edited `?kind=cert.issued` — every time an unrelated
 * group chip is toggled. */
function toggleGroups(current: EventKind[], selectedLabels: string[], nextLabels: string[]): EventKind[] {
  const added = nextLabels.filter((l) => !selectedLabels.includes(l));
  const removed = selectedLabels.filter((l) => !nextLabels.includes(l));
  let k = current;
  for (const label of added) {
    const g = KIND_GROUPS.find((x) => x.label === label)!;
    k = Array.from(new Set([...k, ...g.kinds]));
  }
  for (const label of removed) {
    const g = KIND_GROUPS.find((x) => x.label === label)!;
    k = k.filter((kk) => !g.kinds.includes(kk));
  }
  return ALL_KINDS.filter((kk) => k.includes(kk));
}

export function EventsPage() {
  const org = useOrg();
  const { kind, severity } = useSearch({ from: '/_app/o/$org/alerts/events' });
  const navigate = useNavigate({ from: '/o/$org/alerts/events' });
  const list = useInfiniteQuery(eventsQuery(org.id, { kind, severity }));
  const events = list.data?.pages.flatMap((p) => p.items) ?? [];

  const set = (patch: { kind?: EventKind[]; severity?: Severity }) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });
  const clear = () => void navigate({ search: {} });

  const groups = selectedGroups(kind);
  const onGroupsChange = (next: string[]) => {
    const k = toggleGroups(kind ?? [], groups, next);
    set({ kind: k.length > 0 ? k : undefined });
  };

  const severityValue: SeverityFilter = severity === 'critical' ? 'critical' : severity === 'warning' ? 'warning' : 'all';
  const onSeverityChange = (v: SeverityFilter) => set({ severity: v === 'all' ? undefined : v });

  // Batch 2 review: a kind that isn't part of any fully-selected group (a
  // hand-edited or deep-linked partial `?kind`) still counts as an active
  // filter and gets its own removable chip, by KIND_LABEL.
  const groupKinds = new Set(groups.flatMap((label) => KIND_GROUPS.find((g) => g.label === label)!.kinds));
  const leftoverKinds = (kind ?? []).filter((k) => !groupKinds.has(k));
  const chips = [
    ...groups.map((g) => ({ key: `group:${g}`, label: g })),
    ...leftoverKinds.map((k) => ({ key: `kind:${k}`, label: KIND_LABEL[k] })),
    ...(severityValue !== 'all'
      ? [
          {
            key: 'severity',
            label: severityValue === 'critical' ? 'Critical' : 'Warning+',
          },
        ]
      : []),
  ];
  const removeChip = (key: string) => {
    if (key === 'severity') {
      onSeverityChange('all');
      return;
    }
    if (key.startsWith('kind:')) {
      const k = key.slice('kind:'.length);
      const next = (kind ?? []).filter((kk) => kk !== k);
      set({ kind: next.length > 0 ? next : undefined });
      return;
    }
    onGroupsChange(groups.filter((g) => `group:${g}` !== key));
  };

  // Batch 2 review: derived from the URL directly, not from `chips.length`,
  // so a partial-group deep link is never mistaken for "no filter active".
  const filtered = (kind?.length ?? 0) > 0 || severityValue !== 'all';
  const empty = !list.isPending && events.length === 0;
  const header = (
    <AlertsHeader
      help="alerts.events"
      activeFilters={chips.length}
      filters={
        <>
          <ChipSet
            aria-label="Event groups"
            value={groups}
            onChange={onGroupsChange}
            options={KIND_GROUPS.map((g) => ({
              value: g.label,
              label: g.label,
            }))}
          />
          <div className="grid gap-1.5">
            <span className="inline-flex items-center gap-1 text-xs font-medium text-ink-muted">
              Severity
              <HelpTip id="event.severity" />
            </span>
            <SegmentedControl
              aria-label="Severity"
              size="sm"
              value={severityValue}
              onChange={onSeverityChange}
              options={[
                { value: 'all', label: 'All' },
                { value: 'warning', label: 'Warning+' },
                { value: 'critical', label: 'Critical' },
              ]}
            />
          </div>
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

  return (
    <>
      {header}
      <div className="grid gap-4">
        <FilterChips chips={chips} onRemove={removeChip} onClear={clear} />
        {empty ? (
          filtered ? (
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
          )
        ) : (
          <Card role="list" aria-label="Events" className="px-4 [&>*:last-child]:border-b-0">
            {list.isPending
              ? [0, 1, 2].map((i) => <div key={i} aria-hidden className="h-16 animate-pulse border-b border-border bg-subtle/40" />)
              : events.map((e) => <EventRow key={e.id} event={e} org={org.slug} />)}
          </Card>
        )}
        {list.hasNextPage && (
          <Button variant="outline" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            Load more
          </Button>
        )}
      </div>
    </>
  );
}
