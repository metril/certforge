import { CircleCheck, CircleDashed, CirclePause, Clock, ShieldAlert, Unplug, type LucideIcon } from 'lucide-react';
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
 * Unreachable is the only state that carries a `lastError` tooltip.
 */
export function MonitorStateChip({ state, enabled, lastError }: { state: MonitorState; enabled: boolean; lastError?: string | null }) {
  if (!enabled) return <ToneChip tone="neutral" icon={CirclePause} label="Paused" />;
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
