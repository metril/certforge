import { useId, useState, type ReactNode } from 'react';
import { ChevronRight } from 'lucide-react';
import { HelpTip } from '@/components/HelpTip';
import type { HelpKey } from '@/lib/help';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

export type FormSectionProps = {
  title: string;
  /** One HelpTip beside the title (a `help.ts` key). */
  help?: HelpKey;
  /** Right-aligned summary, e.g. "2 overridden" or a "Reset section" button. */
  summary?: ReactNode;
  /** Render as a closed-by-default disclosure whose trigger is labelled by `title`. */
  collapsible?: boolean;
  /** Collapsible only: start open. */
  defaultOpen?: boolean;
  /** Collapsible only: hidden non-default values; shown as a badge when > 0. */
  count?: number;
  /** Collapsible only: keep open while true (e.g. a field inside has a validation error). */
  forceOpen?: boolean;
  children: ReactNode;
};

/** Titled form group separated by a top border; body is a `gap-4` grid. */
export function FormSection({ title, help, summary, collapsible = false, defaultOpen = false, count = 0, forceOpen = false, children }: FormSectionProps) {
  const [openState, setOpen] = useState(defaultOpen);
  const open = openState || forceOpen;
  const titleId = useId();
  if (!collapsible) {
    return (
      <section aria-labelledby={titleId} className="grid gap-4 border-t border-border pt-4">
        <div className="flex items-center justify-between gap-2">
          <h3 id={titleId} className="flex items-center gap-1.5 text-sm font-semibold">
            {title}
            {help && <HelpTip id={help} />}
          </h3>
          {summary && <div className="text-xs text-ink-muted">{summary}</div>}
        </div>
        {children}
      </section>
    );
  }
  return (
    <Collapsible open={open} onOpenChange={setOpen} asChild>
      <section aria-labelledby={titleId} className="grid gap-4 border-t border-border pt-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <CollapsibleTrigger className="-ml-1 flex items-center gap-1 rounded-sm px-1 text-sm font-semibold hover:text-primary focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none">
              <ChevronRight className={`size-4 transition-transform ${open ? 'rotate-90' : ''}`} aria-hidden />
              <span id={titleId}>{title}</span>
              {count > 0 && (
                <span aria-label={`${count} changed`} className="rounded-full bg-primary px-1.5 text-xs font-medium text-primary-foreground">
                  {count}
                </span>
              )}
            </CollapsibleTrigger>
            {help && <HelpTip id={help} />}
          </div>
          {summary && <div className="text-xs text-ink-muted">{summary}</div>}
        </div>
        <CollapsibleContent className="grid gap-4">{children}</CollapsibleContent>
      </section>
    </Collapsible>
  );
}
