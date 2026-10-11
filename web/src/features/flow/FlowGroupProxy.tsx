import { ChevronRight } from 'lucide-react';
import { ToneChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { FlowStatus } from './flowGraph';
import { CARD, FLOW_STATUS, RAIL, laneArrowKeys } from './FlowNode';

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
          onKeyDown={laneArrowKeys}
          className={cn(CARD, dimmed && 'opacity-40')}
        >
          <span aria-hidden className={cn('absolute inset-y-0 left-0 w-0.75', RAIL[worst])} />
          <span className="flex min-w-0 items-center gap-2">
            <span aria-hidden className="grid size-6 shrink-0 place-items-center rounded-sm bg-subtle">
              <ChevronRight className="size-3.5 text-ink-muted" />
            </span>
            <span className="truncate font-semibold">{title}</span>
            <span className="ml-auto shrink-0 text-xs text-ink-muted">{count}</span>
          </span>
          {worst !== 'valid' && <ToneChip tone={m.tone} icon={m.icon} label={m.label} className="w-fit max-w-full" />}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">Click to expand {title}</TooltipContent>
    </Tooltip>
  );
}
