import { TriangleAlert, Minus } from 'lucide-react';
import { ToneChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { Tone } from '@/lib/status';

/** How a field with no shipped value reads when nothing sets it at any level: a short state, the explanation in a tooltip. */
export type Unset = { label: string; tone?: Tone; tip: string };

/** The one rendering of an unset-everywhere value: a chip when it has a tone, plain text otherwise; both keyboard focusable, with the tip as a tooltip. */
export function UnsetValue({ unset }: { unset: Unset }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {unset.tone ? (
          <ToneChip tabIndex={0} tone={unset.tone} icon={unset.tone === 'expiring' ? TriangleAlert : Minus} label={unset.label} />
        ) : (
          <span tabIndex={0} className="text-sm text-ink-muted">
            {unset.label}
          </span>
        )}
      </TooltipTrigger>
      <TooltipContent>{unset.tip}</TooltipContent>
    </Tooltip>
  );
}
