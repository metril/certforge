import { useId, type ReactNode } from 'react';
import { HelpTip } from '@/components/HelpTip';
import type { HelpKey } from '@/lib/help';
import { Button } from '@/components/ui/button';

export type FilterToolbarProps = {
  /** The labelled controls (`FilterField`s), left-aligned. */
  children: ReactNode;
  /** Active-filter count; the Clear button shows only when > 0. */
  activeFilters?: number;
  onClear?: () => void;
  /** Extra trailing content beside Clear (e.g. SavedViews), pushed right. */
  trailing?: ReactNode;
};

/** A full-width bar that frames a list page's filter controls. */
export function FilterToolbar({ children, activeFilters = 0, onClear, trailing }: FilterToolbarProps) {
  const showClear = activeFilters > 0 && onClear != null;
  return (
    <div role="search" aria-label="Filters" className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border border-border bg-subtle px-3 py-2">
      {children}
      {(showClear || trailing) && (
        <div className="ml-auto flex items-center gap-2">
          {showClear && (
            <Button variant="ghost" size="sm" onClick={onClear}>
              Clear filters
            </Button>
          )}
          {trailing}
        </div>
      )}
    </div>
  );
}

/** An inline label to the left of one control; controls inside are h-8. */
export function FilterField({ label, help, children }: { label: string; help?: HelpKey; children: ReactNode }) {
  const id = useId();
  return (
    <div className="flex items-center gap-2 [&_[role=combobox]]:h-8 [&_[role=group]]:min-h-8 [&_[role=group]]:p-[3px] [&_[role=radio]]:h-6 [&_input]:h-8">
      <span className="flex items-center gap-1 text-xs text-ink-muted">
        <span id={id}>{label}</span>
        {help && <HelpTip id={help} />}
      </span>
      <div role="group" aria-labelledby={id} className="contents">
        {children}
      </div>
    </div>
  );
}
