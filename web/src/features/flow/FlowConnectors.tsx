import { Fragment, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type RefObject } from 'react';
import { edgeRelation } from './flowLabels';
import { FLOW_STATUS } from './FlowNode';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { collapseEdges, edgeKey, isProxyId, laneIndex, pairStatus, proxyLaneIndex, type Flow, type FlowNodeData, type FlowPath, type FlowStatus } from './flowGraph';

const STROKE: Record<FlowStatus, string> = {
  valid: 'stroke-valid',
  expiring: 'stroke-expiring',
  expired: 'stroke-expired',
  failed: 'stroke-failed',
  drift: 'stroke-drift',
  pending: 'stroke-pending',
  idle: 'stroke-ink-muted',
};

const FILL: Record<FlowStatus | 'muted' | 'input', string> = {
  valid: 'fill-valid',
  expiring: 'fill-expiring',
  expired: 'fill-expired',
  failed: 'fill-failed',
  drift: 'fill-drift',
  pending: 'fill-pending',
  idle: 'fill-ink-muted',
  muted: 'fill-ink-muted',
  input: 'fill-input',
};
const MARKERS = Object.keys(FILL) as (keyof typeof FILL)[];
const markerOf = (cls: string): keyof typeof FILL => (cls === 'stroke-input' ? 'input' : cls === 'stroke-ink-muted' ? 'muted' : (cls.slice('stroke-'.length) as FlowStatus));

type Line = {
  key: string;
  d: string;
  cls: string;
  width: number;
  opacity: number;
  dashed: boolean;
  hover: boolean;
  /** Real node pair, left lane first; null for proxies and synthetic links, which are not interactive. */
  ends: { from: string; to: string } | null;
  status: FlowStatus;
  label: string;
  mx: number;
  my: number;
};
type Props = {
  containerRef: RefObject<HTMLElement | null>;
  getEl: (id: string) => HTMLElement | undefined;
  flow: Flow;
  path: FlowPath;
  /** Path of the hovered node, lit lighter than the selection. */
  hoverPath?: FlowPath;
  selected: boolean;
  /** The selected connection, left lane first. */
  selectedEdge?: { from: string; to: string };
  onSelectEdge?: (from: string, to: string) => void;
  /** Collapsed group ids; their members are drawn as one proxy row. */
  collapsed: Set<string>;
};

/** One SVG overlay behind the nodes: cubic curves from the right edge of the
 * left node to the left edge of the right node, measured from the live DOM. */
export function FlowConnectors({ containerRef, getEl, flow, path, hoverPath, selected, selectedEdge, onSelectEdge, collapsed }: Props) {
  const [lines, setLines] = useState<Line[]>([]);
  const [hoverEdge, setHoverEdge] = useState<string | null>(null);
  const raf = useRef(0);

  const kinds = useMemo(() => {
    const m = new Map<string, FlowNodeData['kind']>();
    for (const l of Object.values(flow.lanes)) for (const n of l.nodes) m.set(n.id, n.kind);
    return m;
  }, [flow]);
  const names = useMemo(() => {
    const m = new Map<string, string>();
    for (const l of Object.values(flow.lanes)) for (const n of l.nodes) m.set(n.id, n.name);
    return m;
  }, [flow]);
  const nameOf = (id: string) => names.get(id) ?? id;
  const merged = useMemo(() => collapseEdges(flow, collapsed, path.synthetic), [flow, collapsed, path.synthetic]);

  const measure = useCallback(() => {
    const box = containerRef.current;
    if (!box) return;
    const origin = box.getBoundingClientRect();
    const lane = (id: string): number | undefined => {
      if (isProxyId(id)) return proxyLaneIndex(id);
      const k = kinds.get(id);
      return k ? laneIndex(k) : undefined;
    };

    const out: Line[] = [];
    for (const m of merged) {
      const la = lane(m.a);
      const lb = lane(m.b);
      const ea = getEl(m.a);
      const eb = getEl(m.b);
      if (la === undefined || lb === undefined || !ea || !eb) continue;
      const [left, right] = la <= lb ? [ea, eb] : [eb, ea];
      const [lid, rid] = la <= lb ? [m.a, m.b] : [m.b, m.a];
      const lr = left.getBoundingClientRect();
      const rr = right.getBoundingClientRect();
      const x1 = lr.right - origin.left;
      const y1 = lr.top + lr.height / 2 - origin.top;
      const x2 = rr.left - origin.left;
      const y2 = rr.top + rr.height / 2 - origin.top;
      const dx = Math.max(24, (x2 - x1) / 2);
      const d = `M${x1} ${y1} C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`;
      const on = m.synthetic || m.keys.some((k) => path.edges.has(k));
      const hov = !on && !!hoverPath && (m.synthetic ? m.keys.some((k) => hoverPath.synthetic.has(k)) : m.keys.some((k) => hoverPath.edges.has(k)));
      const interactive = !m.synthetic && !isProxyId(m.a) && !isProxyId(m.b);
      const st = m.edges.length > 0 ? pairStatus(m.edges, path.nodes) : 'idle';
      out.push({
        key: m.key,
        ends: interactive ? { from: lid, to: rid } : null,
        status: st,
        label: interactive ? edgeRelation(kinds.get(lid)!, kinds.get(rid)!) : '',
        mx: (x1 + x2) / 2,
        my: (y1 + y2) / 2,
        hover: hov,
        d,
        // Nothing selected: one neutral control-border stroke. A selected path
        // is thicker and status-coloured; every other line is dimmed.
        cls: hov ? (m.synthetic ? 'stroke-ink-muted' : STROKE[pairStatus(m.edges, hoverPath.nodes)]) : !selected || !on ? 'stroke-input' : m.synthetic ? 'stroke-ink-muted' : STROKE[pairStatus(m.edges, path.nodes)],
        width: hov ? 2 : !selected ? 1.5 : on ? 2.5 : 1,
        opacity: hov ? 0.7 : !selected ? 1 : on ? 1 : 0.2,
        dashed: m.synthetic,
      });
    }
    setLines((prev) =>
      prev.length === out.length && prev.every((l, i) => {
        const n = out[i];
        return l.key === n.key && l.d === n.d && l.cls === n.cls && l.width === n.width && l.opacity === n.opacity && l.dashed === n.dashed && l.hover === n.hover && l.mx === n.mx && l.my === n.my && l.status === n.status && l.label === n.label && l.ends?.from === n.ends?.from && l.ends?.to === n.ends?.to;
      })
        ? prev
        : out,
    );
  }, [containerRef, getEl, kinds, merged, path, hoverPath, selected]);

  const schedule = useCallback(() => {
    cancelAnimationFrame(raf.current);
    raf.current = requestAnimationFrame(measure);
  }, [measure]);

  useLayoutEffect(() => {
    measure();
  }, [measure]);

  useEffect(() => {
    const box = containerRef.current;
    const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(schedule);
    if (box) ro?.observe(box);
    schedule();
    window.addEventListener('resize', schedule);
    window.addEventListener('scroll', schedule, true);
    return () => {
      ro?.disconnect();
      window.removeEventListener('resize', schedule);
      window.removeEventListener('scroll', schedule, true);
      cancelAnimationFrame(raf.current);
    };
  }, [containerRef, schedule]);

  const selKey = selectedEdge ? edgeKey(selectedEdge.from, selectedEdge.to) : null;
  const chips = lines.filter((l) => l.ends && (l.key === hoverEdge || l.key === selKey));
  return (
    <>
      <svg aria-hidden data-flow-connectors className="pointer-events-none absolute inset-0 z-0 size-full overflow-visible">
        <defs>
          {MARKERS.map((m) => (
            <marker key={m} id={`flow-arrow-${m}`} viewBox="0 0 8 8" refX="8" refY="4" markerWidth="8" markerHeight="8" markerUnits="userSpaceOnUse" orient="auto">
              <path d="M0 0 L8 4 L0 8 z" className={FILL[m]} />
            </marker>
          ))}
        </defs>
        {lines.map((l) => (
          <g key={l.key} opacity={l.opacity}>
            <path
              d={l.d}
              fill="none"
              className={l.cls}
              strokeWidth={l.width}
              strokeDasharray={l.dashed ? '4 4' : undefined}
              markerEnd={`url(#flow-arrow-${markerOf(l.cls)})`}
              data-edge={l.key}
              data-dashed={l.dashed || undefined}
              data-hover-path={l.hover || undefined}
              data-selected={l.key === selKey || undefined}
            />
            {l.ends && (
              <path
                d={l.d}
                fill="none"
                stroke="transparent"
                strokeWidth={12}
                className="cursor-pointer"
                style={{ pointerEvents: 'stroke' }}
                data-edge-hit={l.key}
                onPointerEnter={() => setHoverEdge(l.key)}
                onPointerLeave={() => setHoverEdge(null)}
                onClick={() => onSelectEdge?.(l.ends!.from, l.ends!.to)}
              />
            )}
          </g>
        ))}
      </svg>
      <div className="pointer-events-none absolute inset-0 z-20">
        {chips.map((l) => (
          <Fragment key={l.key}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  tabIndex={-1}
                  style={{ left: l.mx, top: l.my }}
                  onPointerEnter={() => setHoverEdge(l.key)}
                  onPointerLeave={() => setHoverEdge(null)}
                  onClick={() => onSelectEdge?.(l.ends!.from, l.ends!.to)}
                  className="pointer-events-auto absolute -translate-x-1/2 -translate-y-1/2 rounded-sm border border-border bg-raised px-1.5 text-xs whitespace-nowrap text-ink-muted shadow-ctl"
                >
                  {l.label} · {FLOW_STATUS[l.status].label.toLowerCase()}
                </button>
              </TooltipTrigger>
              <TooltipContent>{`From ${nameOf(l.ends!.from)} to ${nameOf(l.ends!.to)}. Click to select.`}</TooltipContent>
            </Tooltip>
          </Fragment>
        ))}
      </div>
    </>
  );
}
