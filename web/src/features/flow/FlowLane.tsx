import { Link } from '@tanstack/react-router';
import { ChevronRight, Lock } from 'lucide-react';
import { cn } from '@/lib/utils';
import { SUBGROUPS, proxyId, worstStatus, type FlowNodeData, type FlowStatus, type LaneKey } from './flowGraph';
import { FlowGroupProxy } from './FlowGroupProxy';
import { FlowNode } from './FlowNode';

export const LANE_META: Record<LaneKey, { title: string; empty: string; cta: string; to: '/o/$org/issuers' | '/o/$org/certificates/new' | '/o/$org/delivery' | '/o/$org/clients/new' | '/o/$org/alerts/channels' }> = {
  issuers: { title: 'Issuers', empty: 'No issuers yet.', cta: 'Add an issuer', to: '/o/$org/issuers' },
  certificates: { title: 'Certificates', empty: 'No certificates yet.', cta: 'Create a certificate', to: '/o/$org/certificates/new' },
  delivery: { title: 'Delivery', empty: 'Nothing delivers certificates yet.', cta: 'Set up delivery', to: '/o/$org/delivery' },
  clients: { title: 'Clients', empty: 'No clients yet.', cta: 'Add a client', to: '/o/$org/clients/new' },
  alerts: { title: 'Alerts', empty: 'No alert channels yet.', cta: 'Add a channel', to: '/o/$org/alerts/channels' },
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
  onSelect: (id: string) => void;
  register: (id: string, el: HTMLElement | null) => void;
  /** Collapsed group ids (lanes and sub-groups). */
  collapsed: Set<string>;
  onToggle: (groupId: string) => void;
};

const isProblem = (s: FlowStatus) => s !== 'valid' && s !== 'idle';

type HeadProps = { title: string; count: string; total: number; problems: number; open: boolean; onToggle: () => void; sub?: boolean };

/** Heading button of a lane or sub-group: chevron, title, count and problems. */
function GroupHead({ title, count, total, problems, open, onToggle, sub }: HeadProps) {
  return (
    <button
      type="button"
      aria-expanded={open}
      onClick={onToggle}
      className={cn('flex w-full min-w-0 items-center gap-1.5 rounded-sm text-left focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none', sub ? 'text-xs text-ink-muted' : 'items-baseline pb-0 text-sm font-semibold')}
    >
      <ChevronRight className={cn('size-3.5 shrink-0 self-center text-ink-muted transition-transform', open && 'rotate-90')} aria-hidden />
      <span className="truncate">{title}</span>
      <span className="ml-auto shrink-0 text-xs font-normal text-ink-muted">
        <span aria-label={`${count} of ${total}`}>{count}</span>
        {problems > 0 && <span className="text-failed"> · {problems} {problems === 1 ? 'problem' : 'problems'}</span>}
      </span>
    </button>
  );
}

export function FlowLane({ laneKey, org, hidden, nodes, total, selectedId, onPath, onSelect, register, collapsed, onToggle }: Props) {
  const meta = LANE_META[laneKey];
  const item = (n: FlowNodeData) => (
    <li key={n.id} className="min-w-0">
      <FlowNode node={n} selected={n.id === selectedId} dimmed={!!onPath && !onPath.has(n.id)} onSelect={onSelect} register={register} />
    </li>
  );
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
          onExpand={() => onToggle(gid)}
          register={register}
        />
      </li>
    </ul>
  );
  const laneOpen = !collapsed.has(laneKey);
  const countText = nodes.length === total ? String(total) : `${nodes.length}/${total}`;
  const interactive = !hidden && total > 0;
  return (
    <section aria-label={meta.title} data-flow-lane={laneKey} className="relative z-10 grid min-w-0 content-start gap-2">
      <h2 className="border-b border-border pb-1 text-sm font-semibold">
        {interactive ? (
          <GroupHead title={meta.title} count={countText} total={total} problems={nodes.filter((n) => isProblem(n.status)).length} open={laneOpen} onToggle={() => onToggle(laneKey)} />
        ) : (
          <span className="flex items-baseline justify-between gap-2">
            {meta.title}
            {!hidden && (
              <span className="text-xs font-normal text-ink-muted" aria-label={`${nodes.length} of ${total}`}>
                {countText}
              </span>
            )}
          </span>
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
                <h3>
                  <GroupHead sub title={g.title} count={String(ns.length)} total={ns.length} problems={ns.filter((n) => isProblem(n.status)).length} open={open} onToggle={() => onToggle(g.id)} />
                </h3>
                {open ? <ul className="grid gap-2">{ns.map(item)}</ul> : proxy(g.id, g.title, ns)}
              </div>
            );
          })}
        </div>
      ) : (
        <ul className="grid gap-2">{nodes.map(item)}</ul>
      )}
    </section>
  );
}
