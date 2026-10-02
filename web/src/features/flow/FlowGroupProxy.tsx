import { ChevronRight } from 'lucide-react';
import { ToneChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { FlowStatus } from './flowGraph';
import { FLOW_STATUS } from './FlowNode';

type Props = {
  /** Element id the connectors measure (proxyId of the group). */
  id: string;
  title: string;
  count: number;
  worst: FlowStatus;
  dimmed: boolean;
  onExpand: () => void;
  register: (id: string, el: HTMLElement | null) => void;
};

/** One row standing in for a collapsed group, shaped like a node card. */
export function FlowGroupProxy({ id, title, count, worst, dimmed, onExpand, register }: Props) {
  const m = FLOW_STATUS[worst];
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          data-flow-proxy
          data-node-id={id}
          ref={(el) => register(id, el)}
          aria-label={`Expand ${title}, ${count} ${count === 1 ? 'item' : 'items'}, ${m.label}`}
          onClick={onExpand}
          className={cn(
            'relative z-10 grid w-full min-w-0 gap-1.5 rounded-md border border-border bg-panel px-2.5 py-2 text-left text-sm transition-opacity hover:border-ink-muted focus-visible:border-primary focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none',
            dimmed && 'opacity-40',
          )}
        >
          <span className="flex min-w-0 items-center gap-2">
            <ChevronRight className="size-4 shrink-0 text-ink-muted" aria-hidden />
            <span className="truncate font-semibold">{title}</span>
            <span className="ml-auto shrink-0 text-xs text-ink-muted">{count}</span>
          </span>
          <ToneChip tone={m.tone} icon={m.icon} label={m.label} className="w-fit max-w-full" />
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">Click to expand {title}</TooltipContent>
    </Tooltip>
  );
}
