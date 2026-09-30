import { ToneChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { RUNS_ON_META, type RunsOnMode } from '@/lib/targets';

/** Where a deploy target type runs (UI conventions, R12): server -> Server
 * "Server", agent -> Cpu "Agent", either -> ArrowLeftRight "Server or
 * agent". `compact` (below `sm`, so two type segments fit at 375px) shows
 * only the icon, with the word moved to `aria-label` and a hover/focus
 * tooltip. */
export function RunsOnChip({ mode, compact = false }: { mode: RunsOnMode; compact?: boolean }) {
  const { label, icon } = RUNS_ON_META[mode];
  const chip = <ToneChip tone="neutral" icon={icon} label={compact ? '' : label} aria-label={compact ? label : undefined} />;
  if (!compact) return chip;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{chip}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}
