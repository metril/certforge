import { useEffect, useRef } from 'react';
import { Link } from '@tanstack/react-router';
import { ChevronRight, Lock } from 'lucide-react';
import type { HelpKey } from '@/lib/help';
import { cn } from '@/lib/utils';
import { CAP, SUBGROUPS, isProblem, sortForLane, proxyId, worstStatus, type FlowNodeData, type LaneKey } from './flowGraph';
import { FlowGroupProxy } from './FlowGroupProxy';
import { FlowNode, laneArrowKeys } from './FlowNode';
import { HelpTip } from '@/components/HelpTip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

type LaneRoute = '/o/$org/issuers' | '/o/$org/certificates' | '/o/$org/delivery' | '/o/$org/clients' | '/o/$org/alerts/channels';

export const LANE_META: Record<LaneKey, { title: string; empty: string; cta: string; to: '/o/$org/issuers' | '/o/$org/certificates/new' | '/o/$org/delivery' | '/o/$org/clients/new' | '/o/$org/alerts/channels'; list: LaneRoute }> = {
  issuers: { title: 'Issuers', empty: 'No issuers yet.', cta: 'Add an issuer', to: '/o/$org/issuers', list: '/o/$org/issuers' },
  certificates: { title: 'Certificates', empty: 'No certificates yet.', cta: 'Create a certificate', to: '/o/$org/certificates/new', list: '/o/$org/certificates' },
  delivery: { title: 'Delivery', empty: 'Nothing delivers certificates yet.', cta: 'Set up delivery', to: '/o/$org/delivery', list: '/o/$org/delivery' },
  clients: { title: 'Clients', empty: 'No clients yet.', cta: 'Add a client', to: '/o/$org/clients/new', list: '/o/$org/clients' },
  alerts: { title: 'Alerts', empty: 'No alert channels yet.', cta: 'Add a channel', to: '/o/$org/alerts/channels', list: '/o/$org/alerts/channels' },
};

type Props = {
  laneKey: LaneKey;
  org: string;
  hidden: boolean;
  nodes: FlowNodeData[];
  /** Total nodes in the lane before any path filter. */
  total: number;
  selectedId?: string;
  /** Ids on the selected path; undefined when nothing is selected. */
  onPath?: Set<string>;
  /** Ids on the hovered node's path; undefined when nothing is hovered. */
  hoverPath?: Set<string>;
  onHover?: (id: string | null) => void;
  onSelect: (id: string) => void;
  register: (id: string, el: HTMLElement | null) => void;
  /** Collapsed group ids (lanes and sub-groups). */
  collapsed: Set<string>;
  onToggle: (groupId: string) => void;
  /** Group ids shown past the cap. */
  more: Set<string>;
  onMore: (groupId: string) => void;
  /** Ids that stay drawn past the cap (the selection and its connection ends). */
  keep: Set<string>;
  /** Nodes the server's size cap dropped from this lane. */
  omitted: number;
  /** Narrow layout: nodes show their link counts instead of connectors. */
  compact: boolean;
  links: Map<string, { up: number; down: number }>;
};

type HeadProps = { id: string; title: string; count: string; total: number; problems: number; open: boolean; onToggle: () => void; sub?: boolean; help?: HelpKey };

/** Count pill and problem count that follow a group title. */
function Counts({ count, total, problems }: { count: string; total: number; problems: number }) {
  return (
    <>
      <span className="shrink-0 rounded-sm bg-subtle px-1.5 text-xs font-normal tabular-nums text-ink-muted" aria-label={`${count} of ${total}`}>
        {count}
      </span>
      {problems > 0 && <span className="shrink-0 text-xs font-normal text-failed">{problems} {problems === 1 ? 'problem' : 'problems'}</span>}
    </>
  );
}

/** Heading of a lane or sub-group: a chevron button with the title, then count, problems and help. */
function GroupHead({ id, title, count, total, problems, open, onToggle, sub, help }: HeadProps) {
  return (
    <>
      <button
        type="button"
        aria-expanded={open}
        data-group-head={id}
        onClick={onToggle}
        className={cn('flex min-w-0 flex-1 items-center gap-1.5 rounded-sm text-left focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none', sub ? 'text-xs text-ink-muted' : 'text-xs font-semibold tracking-wide text-ink-muted uppercase')}
      >
        <ChevronRight className={cn('size-3.5 shrink-0 transition-transform', open && 'rotate-90')} aria-hidden />
        <span className="truncate">{title}</span>
      </button>
      <Counts count={count} total={total} problems={problems} />
      {help && <HelpTip id={help} label={title} />}
    </>
  );
}

export function FlowLane({ laneKey, org, hidden, nodes, total, selectedId, onPath, hoverPath, onHover, onSelect, register, collapsed, onToggle, more, onMore, keep, omitted, compact, links }: Props) {
  const meta = LANE_META[laneKey];
  const section = useRef<HTMLElement>(null);
  // Expanding a proxy unmounts it, so keyboard focus moves to that group's heading.
  const refocus = useRef<string | null>(null);
  useEffect(() => {
    const id = refocus.current;
    if (!id || collapsed.has(id)) return;
    refocus.current = null;
    section.current?.querySelector<HTMLElement>(`[data-group-head="${id}"]`)?.focus();
  }, [collapsed]);
  const item = (n: FlowNodeData) => (
    <li key={n.id} className="min-w-0">
      <FlowNode node={n} selected={n.id === selectedId} dimmed={!!onPath && !onPath.has(n.id)} hovered={!!hoverPath && hoverPath.has(n.id)} onHover={onHover} onSelect={onSelect} register={register} links={links.get(n.id)} compact={compact} onPath={!!onPath && onPath.has(n.id)} />
    </li>
  );
  /** Up to CAP nodes (problems first) plus any that must stay drawn, then a Show more / Show fewer row. */
  const capped = (gid: string, title: string, ns: FlowNodeData[]) => {
    const sorted = sortForLane(ns);
    const expanded = more.has(gid);
    const shown = expanded ? sorted : sorted.filter((n, i) => i < CAP || keep.has(n.id));
    const rest = sorted.length - shown.length;
    return (
      <ul className="grid gap-2">
        {shown.map(item)}
        {(rest > 0 || (expanded && sorted.length > CAP)) && (
          <li className="min-w-0">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  data-flow-more={gid}
                  aria-expanded={expanded}
                  onClick={() => onMore(gid)}
                  onKeyDown={laneArrowKeys}
                  className="w-full rounded-md border border-dashed border-border px-2.5 py-1.5 text-xs text-ink-muted hover:border-ink-muted hover:text-ink focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none"
                >
                  {expanded ? 'Show fewer' : `Show ${rest} more`}
                </button>
              </TooltipTrigger>
              <TooltipContent>{expanded ? `Show only the first ${CAP} in ${title}` : `Show every item in ${title}`}</TooltipContent>
            </Tooltip>
          </li>
        )}
      </ul>
    );
  };
  const groups = SUBGROUPS[laneKey];
  const proxy = (gid: string, title: string, ns: FlowNodeData[]) => (
    <ul className="grid gap-2">
      <li className="min-w-0">
        <FlowGroupProxy
          id={proxyId(gid)}
          title={title}
          count={ns.length}
          worst={worstStatus(ns.map((n) => n.status))}
          dimmed={!!onPath && !ns.some((n) => onPath.has(n.id))}
          onExpand={() => {
            refocus.current = gid;
            onToggle(gid);
          }}
          register={register}
        />
      </li>
    </ul>
  );
  const laneOpen = !collapsed.has(laneKey);
  const countText = nodes.length === total ? String(total) : `${nodes.length}/${total}`;
  const interactive = !hidden && total > 0;
  return (
    <section ref={section} aria-label={meta.title} data-flow-lane={laneKey} className="relative z-10 grid min-w-0 content-start gap-2">
      <h2 className="sticky top-0 z-20 flex items-center gap-2 border-b border-border bg-surface pb-1 pt-2">
        {interactive ? (
          <GroupHead id={laneKey} title={meta.title} count={countText} total={total} problems={nodes.filter((n) => isProblem(n.status)).length} open={laneOpen} onToggle={() => onToggle(laneKey)} help={`flow.lane.${laneKey}`} />
        ) : (
          <>
            <span className="min-w-0 flex-1 truncate text-xs font-semibold tracking-wide text-ink-muted uppercase">{meta.title}</span>
            {!hidden && <Counts count={countText} total={total} problems={0} />}
            <HelpTip id={`flow.lane.${laneKey}`} label={meta.title} />
          </>
        )}
      </h2>
      {hidden ? (
        <p className="flex items-center gap-1.5 rounded-md border border-dashed border-border px-2.5 py-2 text-xs text-ink-muted">
          <Lock className="size-3.5 shrink-0" aria-hidden />
          No access
        </p>
      ) : total === 0 ? (
        <div className="grid gap-1 rounded-md border border-dashed border-border px-2.5 py-2 text-xs text-ink-muted">
          <p>{meta.empty}</p>
          <Link to={meta.to} params={{ org }} className="font-semibold text-primary hover:underline">
            {meta.cta}
          </Link>
        </div>
      ) : !laneOpen ? (
        nodes.length > 0 && proxy(laneKey, meta.title, nodes)
      ) : groups ? (
        <div className="grid gap-3">
          {groups.map((g) => {
            const ns = nodes.filter((n) => g.kinds.includes(n.kind));
            if (ns.length === 0) return null;
            const open = !collapsed.has(g.id);
            return (
              <div key={g.id} className="grid gap-1.5">
                <h3 className="flex items-center gap-2">
                  <GroupHead sub id={g.id} title={g.title} count={String(ns.length)} total={ns.length} problems={ns.filter((n) => isProblem(n.status)).length} open={open} onToggle={() => onToggle(g.id)} />
                </h3>
                {open ? capped(g.id, g.title, ns) : proxy(g.id, g.title, ns)}
              </div>
            );
          })}
        </div>
      ) : (
        capped(laneKey, meta.title, nodes)
      )}
      {!hidden && omitted > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <p className="text-xs text-ink-muted">
              +{omitted} not shown ·{' '}
              <Link to={meta.list} params={{ org }} className="font-semibold text-primary hover:underline">
                Open {meta.title}
              </Link>
            </p>
          </TooltipTrigger>
          <TooltipContent>The map hit its size limit</TooltipContent>
        </Tooltip>
      )}
    </section>
  );
}
