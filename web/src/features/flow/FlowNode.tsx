import type { KeyboardEvent } from 'react';
import {
  Bell,
  CircleAlert,
  CircleCheck,
  CircleX,
  Clock,
  FileDiff,
  Globe,
  Hourglass,
  KeyRound,
  Landmark,
  LayoutTemplate,
  Minus,
  Send,
  Server,
  ShieldCheck,
  Webhook,
  type LucideIcon,
} from 'lucide-react';
import { ToneChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { Tone } from '@/lib/status';
import { cn } from '@/lib/utils';
import type { FlowNodeData, FlowStatus } from './flowGraph';
import { flowStatusLabel, nodeMeta } from './flowLabels';

export const FLOW_STATUS: Record<FlowStatus, { tone: Tone; icon: LucideIcon; label: string }> = {
  valid: { tone: 'valid', icon: CircleCheck, label: 'Healthy' },
  expiring: { tone: 'expiring', icon: Clock, label: 'Expiring' },
  expired: { tone: 'expired', icon: CircleX, label: 'Expired' },
  failed: { tone: 'failed', icon: CircleAlert, label: 'Failed' },
  drift: { tone: 'drift', icon: FileDiff, label: 'Drift' },
  pending: { tone: 'pending', icon: Hourglass, label: 'Pending' },
  idle: { tone: 'neutral', icon: Minus, label: 'Idle' },
};

/** Solid 3px rail down a card's left edge, by status. */
export const RAIL: Record<FlowStatus, string> = {
  valid: 'bg-valid',
  expiring: 'bg-expiring',
  expired: 'bg-expired',
  failed: 'bg-failed',
  drift: 'bg-drift',
  pending: 'bg-pending',
  idle: 'bg-border',
};

/** Shared card shell; the proxy row mirrors it. */
export const CARD =
  'relative z-10 grid w-full min-w-0 gap-0.5 overflow-hidden rounded-md border border-border bg-panel py-2 pl-3.5 pr-2.5 text-left text-sm transition-opacity hover:border-ink-muted focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none';

export const KIND_META: Record<FlowNodeData['kind'], { icon: LucideIcon; label: string }> = {
  ca: { icon: Landmark, label: 'CA' },
  account: { icon: KeyRound, label: 'ACME account' },
  dnsCredential: { icon: Globe, label: 'DNS credential' },
  certificate: { icon: ShieldCheck, label: 'Certificate' },
  layout: { icon: LayoutTemplate, label: 'Layout' },
  target: { icon: Send, label: 'Target' },
  hook: { icon: Webhook, label: 'Hook' },
  client: { icon: Server, label: 'Client' },
  channel: { icon: Bell, label: 'Channel' },
};

export function FlowChip({ node, className }: { node: Pick<FlowNodeData, 'kind' | 'status' | 'statusDetail'>; className?: string }) {
  const m = FLOW_STATUS[node.status];
  return <ToneChip tone={m.tone} icon={m.icon} label={flowStatusLabel(node.kind, node.status, node.statusDetail)} className={className} />;
}

/** Arrow Up/Down moves focus between the nodes and group proxies of one lane. */
export function laneArrowKeys(e: KeyboardEvent<HTMLButtonElement>) {
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  const lane = e.currentTarget.closest('[data-flow-lane]');
  if (!lane) return;
  const all = [...lane.querySelectorAll<HTMLButtonElement>('button[data-flow-node],button[data-flow-proxy],button[data-flow-more]')];
  const next = all[all.indexOf(e.currentTarget) + (e.key === 'ArrowDown' ? 1 : -1)];
  if (next) {
    e.preventDefault();
    next.focus();
  }
}

type Props = {
  node: FlowNodeData;
  selected: boolean;
  dimmed: boolean;
  /** On the hovered or keyboard-focused node's path (lighter than the selection). */
  hovered?: boolean;
  onHover?: (id: string | null) => void;
  onSelect: (id: string) => void;
  register: (id: string, el: HTMLElement | null) => void;
  /** On the selected node's path. */
  onPath?: boolean;
  links?: { up: number; down: number };
  /** Narrow layout: no connectors are drawn, so the meta line carries link counts. */
  compact?: boolean;
};

export function FlowNode({ node, selected, dimmed, hovered, onHover, onSelect, register, links, onPath, compact }: Props) {
  const Icon = KIND_META[node.kind].icon;
  const meta = nodeMeta(node, links);
  const counts = compact && links;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          data-flow-node
          data-node-id={node.id}
          data-hover-path={hovered ? '' : undefined}
          onPointerEnter={() => onHover?.(node.id)}
          onPointerLeave={() => onHover?.(null)}
          onFocus={(e) => e.currentTarget.matches(':focus-visible') && onHover?.(node.id)}
          onBlur={() => onHover?.(null)}
          ref={(el) => register(node.id, el)}
          aria-pressed={selected}
          aria-label={`${KIND_META[node.kind].label} ${node.name}, ${flowStatusLabel(node.kind, node.status, node.statusDetail)}${meta ? `, ${meta}` : ''}`}
          onClick={() => onSelect(node.id)}
          onKeyDown={laneArrowKeys}
          className={cn(
            CARD,
            onPath && !selected && 'border-primary/60',
            selected && 'border-primary bg-selected shadow-ctl',
            hovered && !selected && 'border-ink-muted',
            dimmed && (hovered ? 'opacity-70' : 'opacity-40'),
          )}
        >
          <span aria-hidden className={cn('absolute inset-y-0 left-0 w-0.75', RAIL[node.status])} />
          <span className="flex min-w-0 items-center gap-2">
            <span aria-hidden className="grid size-6 shrink-0 place-items-center rounded-sm bg-subtle">
              <Icon className="size-3.5 text-ink-muted" />
            </span>
            <span className="truncate font-semibold">{node.name}</span>
          </span>
          {(meta || counts) && (
            <span className="truncate pl-8 text-xs text-ink-muted">
              {meta}
              {meta && counts && ' · '}
              {counts && (
                <span className="tabular-nums" aria-label={`${links.up} upstream, ${links.down} downstream`}>
                  ↑{links.up} ↓{links.down}
                </span>
              )}
            </span>
          )}
          {node.status !== 'valid' && <FlowChip node={node} className="w-fit max-w-full" />}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">
        {node.name}
        {node.statusDetail ? `: ${node.statusDetail}` : ''}
      </TooltipContent>
    </Tooltip>
  );
}
