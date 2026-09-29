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
import { KIND_GROUPS } from '@/lib/events';
import { useOrg } from '@/lib/org';
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

function kindsForGroups(labels: string[]): EventKind[] {
  const groups = KIND_GROUPS.filter((g) => labels.includes(g.label));
  return ALL_KINDS.filter((kk) => groups.some((g) => g.kinds.includes(kk)));
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
    const k = kindsForGroups(next);
    set({ kind: k.length > 0 ? k : undefined });
  };

  const severityValue: SeverityFilter = severity === 'critical' ? 'critical' : severity === 'warning' ? 'warning' : 'all';
  const onSeverityChange = (v: SeverityFilter) => set({ severity: v === 'all' ? undefined : v });

  const chips = [
    ...groups.map((g) => ({ key: `group:${g}`, label: g })),
    ...(severityValue !== 'all' ? [{ key: 'severity', label: severityValue === 'critical' ? 'Critical' : 'Warning+' }] : []),
  ];
  const removeChip = (key: string) => {
    if (key === 'severity') {
      onSeverityChange('all');
      return;
    }
    onGroupsChange(groups.filter((g) => `group:${g}` !== key));
  };

  if (list.isError) {
    return <ErrorState message={`Couldn't load events. ${errorMessage(list.error)}`} onRetry={() => void list.refetch()} />;
  }

  const filtered = chips.length > 0;
  const empty = !list.isPending && events.length === 0;

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-end gap-6">
        <ChipSet aria-label="Event groups" value={groups} onChange={onGroupsChange} options={KIND_GROUPS.map((g) => ({ value: g.label, label: g.label }))} />
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
      </div>
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
        <div role="list" aria-label="Events">
          {list.isPending
            ? [0, 1, 2].map((i) => <div key={i} aria-hidden className="h-16 animate-pulse border-b border-border bg-subtle/40" />)
            : events.map((e) => <EventRow key={e.id} event={e} org={org.slug} />)}
        </div>
      )}
      {list.hasNextPage && (
        <Button variant="outline" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
          Load more
        </Button>
      )}
    </div>
  );
}
