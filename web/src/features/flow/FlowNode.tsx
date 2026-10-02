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

export const FLOW_STATUS: Record<FlowStatus, { tone: Tone; icon: LucideIcon; label: string }> = {
  valid: { tone: 'valid', icon: CircleCheck, label: 'Healthy' },
  expiring: { tone: 'expiring', icon: Clock, label: 'Expiring' },
  expired: { tone: 'expired', icon: CircleX, label: 'Expired' },
  failed: { tone: 'failed', icon: CircleAlert, label: 'Failed' },
  drift: { tone: 'drift', icon: FileDiff, label: 'Drift' },
  pending: { tone: 'pending', icon: Hourglass, label: 'Pending' },
  idle: { tone: 'neutral', icon: Minus, label: 'Idle' },
};

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

export function FlowChip({ status, className }: { status: FlowStatus; className?: string }) {
  const m = FLOW_STATUS[status];
  return <ToneChip tone={m.tone} icon={m.icon} label={m.label} className={className} />;
}

type Props = {
  node: FlowNodeData;
  selected: boolean;
  dimmed: boolean;
  onSelect: (id: string) => void;
  register: (id: string, el: HTMLElement | null) => void;
};

export function FlowNode({ node, selected, dimmed, onSelect, register }: Props) {
  const Icon = KIND_META[node.kind].icon;
  const move = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const lane = e.currentTarget.closest('[data-flow-lane]');
    if (!lane) return;
    const all = [...lane.querySelectorAll<HTMLButtonElement>('button[data-flow-node]')];
    const next = all[all.indexOf(e.currentTarget) + (e.key === 'ArrowDown' ? 1 : -1)];
    if (next) {
      e.preventDefault();
      next.focus();
    }
  };
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          data-flow-node
          data-node-id={node.id}
          ref={(el) => register(node.id, el)}
          aria-pressed={selected}
          aria-label={`${KIND_META[node.kind].label} ${node.name}, ${FLOW_STATUS[node.status].label}`}
          onClick={() => onSelect(node.id)}
          onKeyDown={move}
          className={cn(
            'relative z-10 grid w-full min-w-0 gap-1.5 rounded-md border border-border bg-panel px-2.5 py-2 text-left text-sm transition-opacity hover:border-ink-muted focus-visible:border-primary focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none',
            selected && 'border-primary ring-2 ring-primary/40',
            dimmed && 'opacity-40',
          )}
        >
          <span className="flex min-w-0 items-center gap-2">
            <Icon className="size-4 shrink-0 text-ink-muted" aria-hidden />
            <span className="truncate font-semibold">{node.name}</span>
          </span>
          <FlowChip status={node.status} className="w-fit max-w-full" />
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">
        {node.name}
        {node.statusDetail ? `: ${node.statusDetail}` : ''}
      </TooltipContent>
    </Tooltip>
  );
}
