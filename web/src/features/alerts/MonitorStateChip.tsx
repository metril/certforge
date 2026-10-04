import { CircleCheck, CircleDashed, CirclePause, CircleX, Clock, ShieldAlert, Unplug, type LucideIcon } from 'lucide-react';
import type { MonitorState } from '@/api/types';
import { ToneChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { Tone } from '@/lib/status';

// UI conventions "Monitor states".
const STATE_META: Record<MonitorState, { label: string; tone: Tone; icon: LucideIcon }> = {
  unknown: { label: 'Unknown', tone: 'neutral', icon: CircleDashed },
  ok: { label: 'OK', tone: 'valid', icon: CircleCheck },
  mismatch: { label: 'Mismatch', tone: 'failed', icon: ShieldAlert },
  expiring: { label: 'Expiring', tone: 'expiring', icon: Clock },
  unreachable: { label: 'Unreachable', tone: 'failed', icon: Unplug },
};

/**
 * A monitor's state (Task 4). A disabled monitor always shows Paused
 * regardless of its last-observed state (UI conventions "Monitor states");
 * Unreachable is the only state that carries a `lastError` tooltip. An
 * `expiring` monitor whose leaf is already past `notAfter` reads Expired
 * (the server keeps the state `expiring`).
 */
export function MonitorStateChip({
  state,
  enabled,
  lastError,
  notAfter,
  now = Date.now(),
}: {
  state: MonitorState;
  enabled: boolean;
  lastError?: string | null;
  notAfter?: string | null;
  now?: number;
}) {
  if (!enabled) return <ToneChip tone="neutral" icon={CirclePause} label="Paused" />;
  if (state === 'expiring' && notAfter && Date.parse(notAfter) <= now) {
    return <ToneChip tone="expired" icon={CircleX} label="Expired" />;
  }
  const m = STATE_META[state];
  if (state === 'unreachable' && lastError) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <ToneChip tabIndex={0} tone={m.tone} icon={m.icon} label={m.label} />
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
          {lastError}
        </TooltipContent>
      </Tooltip>
    );
  }
  return <ToneChip tone={m.tone} icon={m.icon} label={m.label} />;
}
