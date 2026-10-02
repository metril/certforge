import { useCallback, useDeferredValue, useEffect, useMemo, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Link2, Search, TriangleAlert } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { flowQuery } from '@/api/queries/flow';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { FilterField } from '@/components/FilterToolbar';
import { PageHeader } from '@/components/PageHeader';
import { SegmentedControl } from '@/components/SegmentedControl';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useOrg } from '@/lib/org';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { LANE_KEYS, expandFor, filterFlow, tracePath, visibleNodeIds, type Flow, type FlowNodeData } from './flowGraph';
import { FlowConnectors } from './FlowConnectors';
import { FlowLane } from './FlowLane';
import { FlowPathPanel } from './FlowPathPanel';

function Skeleton() {
  return (
    <div role="status" aria-label="Loading flow" className="grid gap-4 md:grid-cols-5">
      {LANE_KEYS.map((k) => (
        <div key={k} className="grid content-start gap-2">
          <div className="h-5 animate-pulse rounded-sm bg-subtle" />
          <div className="h-16 animate-pulse rounded-md bg-subtle" />
          <div className="h-16 animate-pulse rounded-md bg-subtle" />
        </div>
      ))}
    </div>
  );
}

export function FlowPage() {
  const org = useOrg();
  const search = useSearch({ from: '/_app/o/$org/flow' });
  const navigate = useNavigate({ from: '/o/$org/flow' });
  const wide = useMediaQuery('(min-width: 1024px)');
  const q = useQuery(flowQuery(org.id));
  const full: Flow | undefined = q.data;
  const text = search.q ?? '';
  const status = search.status;
  const deferredText = useDeferredValue(text);
  const visible = useMemo(() => (full ? visibleNodeIds(full, deferredText, status) : null), [full, deferredText, status]);
  const flow = useMemo(() => (full ? filterFlow(full, visible) : undefined), [full, visible]);
  const activeFilters = (text.trim() ? 1 : 0) + (status ? 1 : 0);

  const els = useRef(new Map<string, HTMLElement>());
  const register = useCallback((id: string, el: HTMLElement | null) => {
    if (el) els.current.set(id, el);
    else els.current.delete(id);
  }, []);
  const getEl = useCallback((id: string) => els.current.get(id), []);
  const box = useRef<HTMLDivElement>(null);

  const all = useMemo(() => (flow ? LANE_KEYS.flatMap((k) => flow.lanes[k].nodes) : []), [flow]);
  const focus = search.focus && all.some((n) => n.id === search.focus) ? search.focus : undefined;
  const selected: FlowNodeData | undefined = all.find((n) => n.id === focus);
  const path = useMemo(() => (flow ? tracePath(flow, focus) : null), [flow, focus]);

  const collapsed = useMemo(() => new Set(search.collapsed ?? []), [search.collapsed]);
  const setCollapsed = useCallback(
    (next: string[]) => void navigate({ search: (s) => ({ ...s, collapsed: next.length > 0 ? next : undefined }), replace: true }),
    [navigate],
  );
  const toggleGroup = useCallback(
    (id: string) => setCollapsed(collapsed.has(id) ? [...collapsed].filter((g) => g !== id) : [...collapsed, id]),
    [collapsed, setCollapsed],
  );
  const allCollapsed = LANE_KEYS.every((k) => collapsed.has(k));
  const clearFilters = useCallback(() => void navigate({ search: (s) => ({ ...s, q: undefined, status: undefined }), replace: true }), [navigate]);
  const setFocus = useCallback(
    (id: string | undefined) => void navigate({ search: (s) => ({ ...s, focus: id }), replace: true }),
    [navigate],
  );
  // A focused node inside a collapsed group is opened so it is drawn (once per focus value).
  const opened = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!search.focus) {
      opened.current = undefined;
      return;
    }
    if (!full || opened.current === search.focus) return;
    opened.current = search.focus;
    const n = LANE_KEYS.flatMap((k) => full.lanes[k].nodes).find((x) => x.id === search.focus);
    const cur = search.collapsed ?? [];
    if (!n) return;
    const next = expandFor(n.kind, cur);
    if (next.length !== cur.length) setCollapsed(next);
  }, [full, search.focus, search.collapsed, setCollapsed]);
  // A focused node the filters hide is deselected.
  const focusHidden = !!search.focus && !!full && !focus;
  useEffect(() => {
    if (focusHidden && visible) setFocus(undefined);
  }, [focusHidden, visible, setFocus]);
  const select = useCallback((id: string) => setFocus(id === focus ? undefined : id), [focus, setFocus]);

  const header = (
    <PageHeader
      title="Flow"
      help="flow.map"
      activeFilters={activeFilters}
      onClearFilters={clearFilters}
      filters={
        <>
          <FilterField label="Search">
            <div className="relative w-full md:w-60">
              <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
              <Input
                aria-label="Filter by name"
                className="pl-8 text-sm"
                placeholder="Filter by name"
                value={text}
                onChange={(e) => void navigate({ search: (s) => ({ ...s, q: e.target.value || undefined }), replace: true })}
              />
            </div>
          </FilterField>
          <FilterField label="Show">
            <SegmentedControl
              aria-label="Show"
              value={status ?? 'all'}
              onChange={(v) => void navigate({ search: (s) => ({ ...s, status: v === 'problems' ? 'problems' : undefined }), replace: true })}
              options={[
                { value: 'all', label: 'All' },
                { value: 'problems', label: 'Problems' },
              ]}
            />
          </FilterField>
        </>
      }
      filtersTrailing={
        <Button variant="ghost" size="sm" onClick={() => setCollapsed(allCollapsed ? [] : [...LANE_KEYS])}>
          {allCollapsed ? 'Expand all' : 'Collapse all'}
        </Button>
      }
      actions={
        <>
          {path && path.synthetic.size > 0 && (
            <Tooltip>
              <TooltipTrigger asChild>
                <ToneChip tone="neutral" icon={Link2} label="Dashed links" tabIndex={0} />
              </TooltipTrigger>
              <TooltipContent>Channels match events by type and severity, not by certificate. Dashed links show which channels would hear about the selected certificates.</TooltipContent>
            </Tooltip>
          )}
          {flow?.truncated && (
            <Tooltip>
              <TooltipTrigger asChild>
                <ToneChip tone="expiring" icon={TriangleAlert} label="Truncated" tabIndex={0} />
              </TooltipTrigger>
              <TooltipContent>The map hit its size limit, so some items are not shown.</TooltipContent>
            </Tooltip>
          )}
        </>
      }
    />
  );

  if (q.isPending) {
    return (
      <>
        {header}
        <Skeleton />
      </>
    );
  }
  if (q.isError || !flow || !path) {
    return (
      <>
        {header}
        <ErrorState message={`Could not load the flow map: ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      </>
    );
  }

  const empty = visible !== null && visible.size === 0;
  const filtering = !wide && !!selected;
  return (
    <div
      onKeyDown={(e) => {
        if (e.key === 'Escape' && focus) setFocus(undefined);
      }}
    >
      {header}
      {selected && <FlowPathPanel selected={selected} nodes={all} path={path} slug={org.slug} compact={!wide} onClear={() => setFocus(undefined)} />}
      {empty ? (
        <EmptyState message="No flows match these filters.">
          <Button variant="outline" onClick={clearFilters}>
            Clear filters
          </Button>
        </EmptyState>
      ) : (
      <div ref={box} className={wide ? 'relative grid grid-cols-5 gap-x-12' : 'grid gap-6'}>
        {LANE_KEYS.map((k) => {
          const lane = flow.lanes[k];
          const nodes = filtering ? lane.nodes.filter((n) => path.nodes.has(n.id)) : lane.nodes;
          if (filtering && nodes.length === 0) return null;
          return (
            <FlowLane
              key={k}
              laneKey={k}
              org={org.slug}
              hidden={lane.hidden}
              nodes={nodes}
              total={full!.lanes[k].nodes.length}
              selectedId={focus}
              onPath={selected && !filtering ? path.nodes : undefined}
              onSelect={select}
              register={register}
              collapsed={collapsed}
              onToggle={toggleGroup}
            />
          );
        })}
        {wide && <FlowConnectors containerRef={box} getEl={getEl} flow={flow} path={path} selected={!!selected} collapsed={collapsed} />}
      </div>
      )}
    </div>
  );
}
