import { Info, TriangleAlert } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { docsHref, firstSentences, help, type Help, type HelpKey } from '@/lib/help';
import { cn } from '@/lib/utils';

export function HelpTip({ id, text, warning = false }: { id?: HelpKey; text?: string; warning?: boolean }) {
  const entry: Help | null = id ? help[id] : text ? { text: firstSentences(text, 2) } : null;
  if (!entry) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={warning ? 'Warning' : 'Help'}
          className={cn(
            'inline-flex size-4 shrink-0 items-center justify-center rounded-sm',
            warning ? 'text-expiring hover:text-ink' : 'text-ink-muted hover:text-ink',
          )}
        >
          {warning ? <TriangleAlert className="size-3.5" aria-hidden /> : <Info className="size-3.5" aria-hidden />}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
        {entry.text}
        {entry.learnMore && (
          <>
            {' '}
            <a href={docsHref(entry.learnMore)} target="_blank" rel="noreferrer" className="underline underline-offset-2">
              Learn more
            </a>
          </>
        )}
      </TooltipContent>
    </Tooltip>
  );
}
