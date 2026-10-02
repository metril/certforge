import { CircleCheck, CircleX, Clock, type LucideIcon } from 'lucide-react';
import type { DeliveryStatus, EventDelivery } from '@/api/types';
import { ToneChip } from '@/components/StatusChip';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
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

const RANK: Record<DeliveryStatus, number> = { failed: 2, pending: 1, delivered: 0 };

/** Worst-outcome label and tone for an event's deliveries (never empty). */
export function summarize(deliveries: readonly EventDelivery[]): { label: string; status: DeliveryStatus } {
  const failed = deliveries.filter((d) => d.status === 'failed').length;
  if (failed > 0) return { label: `${failed} of ${deliveries.length} failed`, status: 'failed' };
  const pending = deliveries.filter((d) => d.status === 'pending').length;
  if (pending > 0) return { label: `${pending} pending`, status: 'pending' };
  return { label: deliveries.length === 1 ? 'Sent' : `${deliveries.length} sent`, status: 'delivered' };
}

/** One chip per event instead of one per channel, so the cell can never
 * outgrow its column; the popover lists every channel with its outcome. */
export function DeliverySummary({ deliveries }: { deliveries: readonly EventDelivery[] }) {
  if (deliveries.length === 0) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0} className="rounded-sm text-xs text-ink-muted outline-none focus-visible:ring-2 focus-visible:ring-ring">
            None
          </span>
        </TooltipTrigger>
        <TooltipContent>No channel matched this event.</TooltipContent>
      </Tooltip>
    );
  }
  const { label, status } = summarize(deliveries);
  const m = META[status];
  const sorted = [...deliveries].sort((a, b) => RANK[b.status] - RANK[a.status]);
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button type="button" aria-label={`Deliveries: ${label}`} className="inline-flex max-w-full rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring">
          <ToneChip tone={m.tone} icon={m.icon} label={label} truncate className="min-w-0 max-w-full" />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 p-3">
        <ul className="grid gap-2.5 text-xs">
          {sorted.map((d) => {
            const dm = META[d.status];
            return (
              <li key={d.channelId} className="grid gap-0.5">
                <div className="flex items-center gap-1.5">
                  <dm.icon className={`size-3.5 shrink-0 ${d.status === 'failed' ? 'text-failed' : d.status === 'delivered' ? 'text-valid' : 'text-pending'}`} aria-label={dm.label} />
                  <span title={d.channelName} className="min-w-0 flex-1 truncate font-medium">
                    {d.channelName}
                  </span>
                  <span className="shrink-0 text-ink-muted">
                    {plural(d.attempts, 'attempt')}
                    {d.deliveredAt ? ` · ${relTime(d.deliveredAt)}` : ''}
                  </span>
                </div>
                {d.status === 'failed' && d.lastError && <p className="break-words pl-5 text-ink-muted">{d.lastError}</p>}
              </li>
            );
          })}
        </ul>
      </PopoverContent>
    </Popover>
  );
}
