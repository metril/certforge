import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type RefObject } from 'react';
import { collapseEdges, isProxyId, laneIndex, pairStatus, proxyLaneIndex, type Flow, type FlowNodeData, type FlowPath, type FlowStatus } from './flowGraph';

const STROKE: Record<FlowStatus, string> = {
  valid: 'stroke-valid',
  expiring: 'stroke-expiring',
  expired: 'stroke-expired',
  failed: 'stroke-failed',
  drift: 'stroke-drift',
  pending: 'stroke-pending',
  idle: 'stroke-ink-muted',
};

type Line = { key: string; d: string; cls: string; width: number; opacity: number; dashed: boolean };
type Props = {
  containerRef: RefObject<HTMLElement | null>;
  getEl: (id: string) => HTMLElement | undefined;
  flow: Flow;
  path: FlowPath;
  selected: boolean;
  /** Collapsed group ids; their members are drawn as one proxy row. */
  collapsed: Set<string>;
};

/** One SVG overlay behind the nodes: cubic curves from the right edge of the
 * left node to the left edge of the right node, measured from the live DOM. */
export function FlowConnectors({ containerRef, getEl, flow, path, selected, collapsed }: Props) {
  const [lines, setLines] = useState<Line[]>([]);
  const raf = useRef(0);

  const kinds = useMemo(() => {
    const m = new Map<string, FlowNodeData['kind']>();
    for (const l of Object.values(flow.lanes)) for (const n of l.nodes) m.set(n.id, n.kind);
    return m;
  }, [flow]);
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
      const lr = left.getBoundingClientRect();
      const rr = right.getBoundingClientRect();
      const x1 = lr.right - origin.left;
      const y1 = lr.top + lr.height / 2 - origin.top;
      const x2 = rr.left - origin.left;
      const y2 = rr.top + rr.height / 2 - origin.top;
      const dx = Math.max(24, (x2 - x1) / 2);
      const d = `M${x1} ${y1} C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`;
      const on = m.synthetic || m.keys.some((k) => path.edges.has(k));
      out.push({
        key: m.key,
        d,
        // Nothing selected: one neutral control-border stroke. A selected path
        // is thicker and status-coloured; every other line is dimmed.
        cls: !selected || !on ? 'stroke-input' : m.synthetic ? 'stroke-ink-muted' : STROKE[pairStatus(m.edges, path.nodes)],
        width: !selected ? 1.5 : on ? 2.5 : 1,
        opacity: !selected ? 1 : on ? 1 : 0.2,
        dashed: m.synthetic,
      });
    }
    setLines(out);
  }, [containerRef, getEl, kinds, merged, path, selected]);

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

  return (
    <svg aria-hidden data-flow-connectors className="pointer-events-none absolute inset-0 z-0 size-full overflow-visible">
      {lines.map((l) => (
        <path
          key={l.key}
          d={l.d}
          fill="none"
          className={l.cls}
          strokeWidth={l.width}
          strokeOpacity={l.opacity}
          strokeDasharray={l.dashed ? '4 4' : undefined}
          data-edge={l.key}
          data-dashed={l.dashed || undefined}
        />
      ))}
    </svg>
  );
}
