import { useRouter } from '@tanstack/react-router';
import type { MouseEvent } from 'react';
import { Button } from '@/components/ui/button';
import { LANE_KEYS, laneOf, type FlowNodeData, type FlowPath } from './flowGraph';
import { LANE_META } from './FlowLane';
import { FlowChip } from './FlowNode';

/** Node hrefs are app paths already carrying the org prefix; anything else gets it added. */
export function resolveHref(href: string, slug: string): string {
  if (href.startsWith('/o/')) return href;
  return `/o/${slug}${href.startsWith('/') ? '' : '/'}${href}`;
}

function OpenLink({ node, slug }: { node: FlowNodeData; slug: string }) {
  const router = useRouter();
  const href = resolveHref(node.href, slug);
  const go = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    router.history.push(href);
  };
  return (
    <a href={href} onClick={go} aria-label={`Open ${node.name}`} className="text-xs font-semibold text-primary hover:underline">
      Open
    </a>
  );
}

type Props = {
  selected: FlowNodeData;
  nodes: FlowNodeData[];
  path: FlowPath;
  slug: string;
  /** Narrow screens: just the summary line, lanes below are filtered instead. */
  compact: boolean;
  onClear: () => void;
};

/** Read-only detail of the selected path: each stage in lane order with its status and an Open link. */
export function FlowPathPanel({ selected, nodes, path, slug, compact, onClear }: Props) {
  const onPath = nodes.filter((n) => path.nodes.has(n.id));
  return (
    <section aria-label="Path" className="mb-4 grid gap-3 rounded-md border border-border bg-panel p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="min-w-0 text-sm">
          <span className="font-semibold">Path</span> <span className="text-ink-muted">through</span> <span className="font-semibold">{selected.name}</span>
          <span className="text-ink-muted"> ({onPath.length})</span>
        </p>
        <div className="flex items-center gap-3">
          {compact && <OpenLink node={selected} slug={slug} />}
          <Button variant="outline" size="sm" onClick={onClear}>
            Clear
          </Button>
        </div>
      </div>
      {!compact && (
        <div className="flex max-h-64 flex-wrap gap-x-6 gap-y-3 overflow-y-auto">
          {LANE_KEYS.map((k) => {
            const ns = onPath.filter((n) => laneOf(n.kind) === k);
            if (ns.length === 0) return null;
            return (
              <div key={k} className="min-w-40 flex-1">
                <h3 className="mb-1 text-xs text-ink-muted">{LANE_META[k].title}</h3>
                <ul className="grid gap-1.5">
                  {ns.map((n) => (
                    <li key={n.id} className="flex min-w-0 items-center justify-between gap-2 text-sm">
                      <span className="grid min-w-0 gap-1">
                        <span className="truncate font-semibold">{n.name}</span>
                        <FlowChip node={n} className="w-fit" />
                      </span>
                      <OpenLink node={n} slug={slug} />
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
