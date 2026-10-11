import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Link2, Search, TriangleAlert } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { flowQuery } from '@/api/queries/flow';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { ChipSet } from '@/components/ChipSet';
import { MultiCombobox } from '@/components/MultiCombobox';
import { FilterField } from '@/components/FilterToolbar';
import { PageHeader } from '@/components/PageHeader';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useOrg } from '@/lib/org';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { LANE_KEYS, PROBLEM_STATUSES, expandFor, filterFlow, highlightSet, parseEdgeKey, visibleNodeIds, type Flow, type FlowNodeData, type FlowStatus } from './flowGraph';
import { FLOW_STATUS, KIND_META } from './FlowNode';
import { FLOW_STATUSES, type FlowSearch } from './search';
import { FlowConnectors } from './FlowConnectors';
import { FlowLane } from './FlowLane';
import { FlowDetailSheet } from './FlowDetailSheet';
import { failedWithoutData } from '@/lib/queryState';

type Kind = FlowNodeData['kind'];
const KIND_GROUPS: { lane: string; kinds: Kind[] }[] = [
  { lane: 'Issuers', kinds: ['ca', 'account', 'dnsCredential'] },
  { lane: 'Certificates', kinds: ['certificate'] },
  { lane: 'Delivery', kinds: ['layout', 'target', 'hook'] },
  { lane: 'Clients', kinds: ['client'] },
  { lane: 'Alerts', kinds: ['channel'] },
];
const KIND_HINT: Record<Kind, string> = {
  ca: 'Show certificate authorities and what depends on them.',
  account: 'Show ACME accounts and what depends on them.',
  dnsCredential: 'Show DNS credentials and what depends on them.',
  certificate: 'Show certificates and their paths.',
  layout: 'Show delivery layouts and their paths.',
  target: 'Show delivery targets and their paths.',
  hook: 'Show hooks and their paths.',
  client: 'Show clients and their paths.',
  channel: 'Show alert channels and their paths.',
};
const STATUS_HINT: Record<FlowStatus, string> = {
  failed: 'Show failed items and their paths.',
  expired: 'Show expired certificates and their paths.',
  drift: 'Show items whose deployed copy differs from the latest version.',
  expiring: 'Show certificates close to expiry.',
  pending: 'Show items still in progress.',
  valid: 'Show healthy items and their paths.',
  idle: 'Show items with nothing to report.',
};
const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));
const orNone = <T,>(v: T[]): T[] | undefined => (v.length > 0 ? v : undefined);

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
  const statuses = useMemo(() => (status === 'problems' ? PROBLEM_STATUSES : (status ?? [])), [status]);
  const kinds = search.kind ?? [];
  const issuers = search.issuer ?? [];
  const clients = search.client ?? [];
  const deferredText = useDeferredValue(text);
  const visible = useMemo(
    () => (full ? visibleNodeIds(full, { q: deferredText, kinds: search.kind, statuses, issuers: search.issuer, clients: search.client }) : null),
    [full, deferredText, search.kind, statuses, search.issuer, search.client],
  );
  const flow = useMemo(() => (full ? filterFlow(full, visible) : undefined), [full, visible]);
  const activeFilters = (text.trim() ? 1 : 0) + (kinds.length > 0 ? 1 : 0) + (statuses.length > 0 ? 1 : 0) + (issuers.length > 0 ? 1 : 0) + (clients.length > 0 ? 1 : 0);
  const setFilter = useCallback((patch: Partial<FlowSearch>) => void navigate({ search: (s) => ({ ...s, ...patch }), replace: true }), [navigate]);
  const options = useMemo(() => {
    const of = (k: (typeof LANE_KEYS)[number]) => (full ? full.lanes[k].nodes.map((n) => ({ value: n.id, label: n.name, group: KIND_META[n.kind].label })) : []);
    return { issuers: of('issuers'), clients: of('clients') };
  }, [full]);

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
  // Hovering (or keyboard-focusing) a node lights its path lighter than a selection; debounced so sweeping across nodes never flickers.
  const [hoverId, setHoverId] = useState<string | null>(null);
  const hoverTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const onHover = useCallback((id: string | null) => {
    clearTimeout(hoverTimer.current);
    hoverTimer.current = setTimeout(() => setHoverId(id), 80);
  }, []);
  useEffect(() => () => clearTimeout(hoverTimer.current), []);
  const lit = useMemo(() => (flow ? highlightSet(flow, focus, hoverId) : null), [flow, focus, hoverId]);
  const path = lit?.focus ?? null;
  const hoverPath = lit && lit.hover.nodes.size > 0 ? lit.hover : undefined;

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
  const clearFilters = useCallback(() => void navigate({ search: (s) => ({ ...s, q: undefined, status: undefined, kind: undefined, issuer: undefined, client: undefined }), replace: true }), [navigate]);
  // A node and a connection are never selected together.
  const setFocus = useCallback(
    (id: string | undefined) => void navigate({ search: (s) => ({ ...s, focus: id, edge: undefined }), replace: true }),
    [navigate],
  );
  const setEdge = useCallback(
    (from: string | undefined, to?: string) => void navigate({ search: (s) => ({ ...s, edge: from && to ? `${from}>${to}` : undefined, focus: undefined }), replace: true }),
    [navigate],
  );
  const edge = useMemo(() => (flow && search.edge ? parseEdgeKey(search.edge, flow) : null), [flow, search.edge]);
  const edgeHidden = !!search.edge && !!full && !edge;
  useEffect(() => {
    if (edgeHidden) setEdge(undefined);
  }, [edgeHidden, setEdge]);
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
  const detailing = !!selected || !!edge;
  const clearDetail = useCallback(() => (selected ? setFocus(undefined) : setEdge(undefined)), [selected, setFocus, setEdge]);
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
          <FilterField label="Kind">
            <div className="flex flex-wrap gap-x-3 gap-y-1.5">
              {KIND_GROUPS.map((g) => (
                <ChipSet<Kind>
                  key={g.lane}
                  aria-label={`Kind: ${g.lane}`}
                  value={kinds.filter((k) => g.kinds.includes(k))}
                  onChange={(v) => setFilter({ kind: orNone([...kinds.filter((k) => !g.kinds.includes(k)), ...v]) })}
                  options={g.kinds.map((k) => ({ value: k, label: KIND_META[k].label, hint: KIND_HINT[k] }))}
                />
              ))}
            </div>
          </FilterField>
          <FilterField label="Status">
            <div className="flex flex-wrap gap-x-3 gap-y-1.5">
              <ChipSet<'problems'>
                aria-label="Quick status"
                value={sameSet(statuses, PROBLEM_STATUSES) ? ['problems'] : []}
                onChange={(v) => setFilter({ status: v.length > 0 ? [...PROBLEM_STATUSES] : undefined })}
                options={[{ value: 'problems', label: 'Problems', hint: 'Show failed, expired, drifted and expiring items with their paths.' }]}
              />
              <ChipSet<FlowStatus>
                aria-label="Status"
                value={[...statuses]}
                onChange={(v) => setFilter({ status: orNone(FLOW_STATUSES.filter((x) => v.includes(x))) })}
                options={FLOW_STATUSES.map((st) => {
                  const Icon = FLOW_STATUS[st].icon;
                  return {
                    value: st,
                    label: (
                      <>
                        <Icon className="size-3.5" aria-hidden />
                        {FLOW_STATUS[st].label}
                      </>
                    ),
                    hint: STATUS_HINT[st],
                  };
                })}
              />
            </div>
          </FilterField>
          <FilterField label="Issuer">
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="w-full md:w-44">
                  <MultiCombobox
                    aria-label="Issuer"
                    hideChips
                    value={issuers}
                    onChange={(v) => setFilter({ issuer: orNone(v) })}
                    options={options.issuers}
                    placeholder="Any issuer"
                    emptyText="No issuers."
                    triggerLabel={(v, labelOf) => (v.length === 1 ? labelOf(v[0]!) : `${v.length} issuers`)}
                  />
                </div>
              </TooltipTrigger>
              <TooltipContent>Keep only certificates from these issuers and everything downstream.</TooltipContent>
            </Tooltip>
          </FilterField>
          <FilterField label="Client">
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="w-full md:w-44">
                  <MultiCombobox
                    aria-label="Client"
                    hideChips
                    value={clients}
                    onChange={(v) => setFilter({ client: orNone(v) })}
                    options={options.clients}
                    placeholder="Any client"
                    emptyText="No clients."
                    triggerLabel={(v, labelOf) => (v.length === 1 ? labelOf(v[0]!) : `${v.length} clients`)}
                  />
                </div>
              </TooltipTrigger>
              <TooltipContent>Keep only the paths that reach these clients.</TooltipContent>
            </Tooltip>
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
  if (failedWithoutData(q) || !flow || !path) {
    return (
      <>
        {header}
        <ErrorState message={`Could not load the flow map: ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      </>
    );
  }

  const empty = visible !== null && visible.size === 0;
  return (
    <div
      onKeyDown={(e) => {
        if (e.key !== 'Escape' || !(focus || edge)) return;
        // Escape inside a text field or an open popover/menu belongs to that control. A node's own
        // tooltip also preventDefaults Escape, so defaultPrevented can't be the test.
        const t = e.target as HTMLElement;
        if (t.closest('input, textarea, select, [role="dialog"], [role="listbox"], [role="menu"], [data-radix-popper-content-wrapper]')) return;
        clearDetail();
      }}
    >
      {header}
      {empty ? (
        <EmptyState message="No flows match these filters.">
          <Button variant="outline" onClick={clearFilters}>
            Clear filters
          </Button>
        </EmptyState>
      ) : (
      <div className={wide ? 'lg:flex lg:items-start lg:gap-6' : undefined}>
      <div ref={box} className={wide ? 'relative grid min-w-0 flex-1 grid-cols-5 gap-x-12' : 'grid gap-6'}>
        {LANE_KEYS.map((k) => {
          const lane = flow.lanes[k];
          return (
            <FlowLane
              key={k}
              laneKey={k}
              org={org.slug}
              hidden={lane.hidden}
              nodes={lane.nodes}
              total={full!.lanes[k].nodes.length}
              selectedId={focus}
              onPath={selected ? path.nodes : undefined}
              hoverPath={hoverPath?.nodes}
              onHover={onHover}
              onSelect={select}
              register={register}
              collapsed={collapsed}
              onToggle={toggleGroup}
            />
          );
        })}
        {wide && <FlowConnectors containerRef={box} getEl={getEl} flow={flow} path={path} hoverPath={hoverPath} selected={!!selected} selectedEdge={edge ?? undefined} onSelectEdge={setEdge} collapsed={collapsed} />}
      </div>
      {detailing && <FlowDetailSheet flow={flow} nodes={all} path={path} node={selected} edge={edge ?? undefined} slug={org.slug} orgId={org.id} wide={wide} onClose={clearDetail} onSelectNode={setFocus} onSelectEdge={setEdge} />}
      </div>
      )}
    </div>
  );
}
