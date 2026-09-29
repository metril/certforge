import { CircleCheck, CircleX, Clock, type LucideIcon } from 'lucide-react';
import type { DeliveryStatus } from '@/api/types';
import { ToneChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { Tone } from '@/lib/status';
import { relTime } from '@/lib/time';

// UI conventions (Delivery chips): pending -> Clock "Pending", delivered ->
// CircleCheck "Delivered", failed -> CircleX "Failed".
const META: Record<DeliveryStatus, { label: string; tone: Tone; icon: LucideIcon }> = {
  pending: { label: 'Pending', tone: 'pending', icon: Clock },
  delivered: { label: 'Delivered', tone: 'valid', icon: CircleCheck },
  failed: { label: 'Failed', tone: 'failed', icon: CircleX },
};

type ChannelProps = {
  /** A channel row's own most recent delivery attempt. */
  kind: 'channel';
  status: DeliveryStatus;
  at: string;
  error?: string | null;
};

type EventProps = {
  /** An event row's per-channel delivery. */
  kind: 'event';
  channelName: string;
  status: DeliveryStatus;
  attempts: number;
  deliveredAt?: string | null;
  lastError?: string | null;
};

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/** Shown on a channel row's own last delivery (UI conventions "Delivery
 * chips"), or on an event row's per-channel delivery (task 5). The visible
 * label differs (the status word for a channel, the channel name for an
 * event); the tooltip always names the status, plus attempt detail and any
 * error, never both a status word and a channel name at once. */
export function DeliveryChip(props: ChannelProps | EventProps) {
  const m = META[props.status];
  const label = props.kind === 'channel' ? m.label : props.channelName;
  const tooltip =
    props.kind === 'channel'
      ? `${m.label} · ${relTime(props.at)}`
      : `${m.label} · ${plural(props.attempts, 'attempt')}${props.deliveredAt ? ` · ${relTime(props.deliveredAt)}` : ''}`;
  const error = props.kind === 'channel' ? props.error : props.lastError;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <ToneChip tabIndex={0} tone={m.tone} icon={m.icon} label={label} />
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
        {tooltip}
        {error && (
          <>
            <br />
            {error}
          </>
        )}
      </TooltipContent>
    </Tooltip>
  );
}
