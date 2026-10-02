import type { ReactNode } from 'react';
import { help, type HelpKey } from '@/lib/help';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

/** Plain-text label whose help copy is a tooltip on the text itself (no help
 * icon). Focusable, so the tooltip is reachable by keyboard. */
export function HintLabel({ id, children, focusable = true }: { id: HelpKey; children: ReactNode; focusable?: boolean }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={focusable ? 0 : undefined} className="cursor-help rounded-sm focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none">
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-72 text-xs">
        {help[id].text}
      </TooltipContent>
    </Tooltip>
  );
}
