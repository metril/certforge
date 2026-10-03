import { Info, TriangleAlert } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { docsHref, firstSentences, help, type Help, type HelpKey } from '@/lib/help';
import { cn } from '@/lib/utils';

/** The standard help tooltip's own body (text, plus a "Learn more" link when
 * the entry has one) — exported so a control that's disabled for a reason
 * named in `help.ts` (batch 1 review: `ca.retiredNoCrl`, `ca.rotateImported`)
 * can show the same tooltip content on itself, not just a bare `entry.text`
 * that silently drops `learnMore`. */
export function HelpTipBody({ entry }: { entry: Help }) {
  return (
    <>
      {entry.text}
      {entry.learnMore && (
        <>
          {' '}
          <a href={docsHref(entry.learnMore)} target="_blank" rel="noreferrer" className="underline underline-offset-2">
            Learn more
          </a>
        </>
      )}
    </>
  );
}

export function HelpTip({ id, text, warning = false, label }: { id?: HelpKey; text?: string; warning?: boolean; label?: string }) {
  const entry: Help | null = id ? help[id] : text ? { text: firstSentences(text, 2) } : null;
  if (!entry) return null;
  const name = warning ? 'Warning' : label ? `Help: ${label}` : 'Help';
  const trigger = (
    <button
      type="button"
      aria-label={name}
      className={cn(
        'inline-flex size-4 shrink-0 items-center justify-center rounded-sm',
        warning ? 'text-expiring hover:text-ink' : 'text-ink-muted hover:text-ink',
      )}
    >
      {warning ? <TriangleAlert className="size-3.5" aria-hidden /> : <Info className="size-3.5" aria-hidden />}
    </button>
  );
  // A tooltip can't hold a link a keyboard user can reach, so entries with a
  // "Learn more" link open a focusable popover instead.
  if (entry.learnMore) {
    return (
      <Popover>
        <PopoverTrigger asChild>{trigger}</PopoverTrigger>
        <PopoverContent side="top" className="w-auto max-w-64 p-2 text-xs leading-snug">
          <HelpTipBody entry={entry} />
        </PopoverContent>
      </Popover>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>{trigger}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
        <HelpTipBody entry={entry} />
      </TooltipContent>
    </Tooltip>
  );
}
