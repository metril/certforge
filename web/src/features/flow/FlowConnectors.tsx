import { useCallback, useEffect, useLayoutEffect, useRef, useState, type RefObject } from 'react';
import { edgeKey, laneIndex, type Flow, type FlowNodeData, type FlowPath, type FlowStatus } from './flowGraph';

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
type Pair = { a: string; b: string; status: FlowStatus | null };

type Props = {
  containerRef: RefObject<HTMLElement | null>;
  getEl: (id: string) => HTMLElement | undefined;
  flow: Flow;
  path: FlowPath;
  selected: boolean;
};

/** One SVG overlay behind the nodes: cubic curves from the right edge of the
 * left node to the left edge of the right node, measured from the live DOM. */
export function FlowConnectors({ containerRef, getEl, flow, path, selected }: Props) {
  const [lines, setLines] = useState<Line[]>([]);
  const raf = useRef(0);

  const measure = useCallback(() => {
    const box = containerRef.current;
    if (!box) return;
    const origin = box.getBoundingClientRect();
    const kinds = new Map<string, FlowNodeData['kind']>();
    for (const l of Object.values(flow.lanes)) for (const n of l.nodes) kinds.set(n.id, n.kind);

    const pairs = new Map<string, Pair>();
    for (const e of flow.edges) {
      const k = edgeKey(e.from, e.to);
      if (!pairs.has(k)) pairs.set(k, { a: e.from, b: e.to, status: e.status });
    }
    for (const k of path.synthetic) {
      const [a, b] = k.split('|');
      pairs.set(`s:${k}`, { a, b, status: null });
    }

    const out: Line[] = [];
    for (const [key, p] of pairs) {
      const ka = kinds.get(p.a);
      const kb = kinds.get(p.b);
      const ea = getEl(p.a);
      const eb = getEl(p.b);
      if (!ka || !kb || !ea || !eb) continue;
      const [left, right] = laneIndex(ka) <= laneIndex(kb) ? [ea, eb] : [eb, ea];
      const lr = left.getBoundingClientRect();
      const rr = right.getBoundingClientRect();
      const x1 = lr.right - origin.left;
      const y1 = lr.top + lr.height / 2 - origin.top;
      const x2 = rr.left - origin.left;
      const y2 = rr.top + rr.height / 2 - origin.top;
      const dx = Math.max(24, (x2 - x1) / 2);
      const d = `M${x1} ${y1} C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`;
      const synthetic = p.status === null;
      const on = synthetic || path.edges.has(key);
      out.push({
        key,
        d,
        cls: synthetic ? 'stroke-ink-muted' : STROKE[p.status ?? 'idle'],
        width: !selected ? 1 : on ? 2.5 : 1,
        opacity: !selected ? 0.35 : on ? 1 : 0.1,
        dashed: synthetic,
      });
    }
    setLines(out);
  }, [containerRef, getEl, flow, path, selected]);

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
