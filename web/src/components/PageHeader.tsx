import type { ReactNode } from 'react';
import { ListFilter } from 'lucide-react';
import { HelpTip } from '@/components/HelpTip';
import type { HelpKey } from '@/lib/help';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { FilterToolbar } from '@/components/FilterToolbar';
import { useMediaQuery } from '@/lib/useMediaQuery';

export type PageHeaderProps = {
  title: ReactNode;
  /** One HelpTip beside the title (a `help.ts` key). */
  help?: HelpKey;
  /** Right-aligned action buttons (one filled button per view). */
  actions?: ReactNode;
  /** Route-link tabs (`<Link className={TAB_LINK} activeProps={TAB_ACTIVE}>`), rendered bare: the header supplies the `<nav>` and the strip border. */
  tabs?: ReactNode;
  /** Accessible name of the tab `<nav>`; defaults to "Sections". */
  tabsLabel?: string;
  /** Filter controls (`FilterField`s). From `md` they sit in a labelled toolbar below the tabs; below `md` they move into a "Filters" popover. */
  filters?: ReactNode;
  /** Active-filter count shown on the mobile "Filters" button when > 0. */
  activeFilters?: number;
  /** Clears every filter; shows a "Clear filters" button in the toolbar when filters are active. */
  onClearFilters?: () => void;
  /** Extra toolbar content pushed right (e.g. SavedViews). */
  filtersTrailing?: ReactNode;
  /** Active-filter chips; shown only inside the mobile popover (desktop controls show their own values). */
  filterChips?: ReactNode;
  /** Extra content under the title (legacy). */
  children?: ReactNode;
};

/** Page header: title (+ help) left, actions right, optional tabs beneath, then a
 * labelled filter toolbar. */
export function PageHeader({ title, help, actions, tabs, tabsLabel = 'Sections', filters, activeFilters = 0, onClearFilters, filtersTrailing, filterChips, children }: PageHeaderProps) {
  const wide = useMediaQuery('(min-width: 768px)');
  const hasFilters = filters != null && filters !== false;
  const filterSlot = !hasFilters || wide ? null : (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="my-1 shrink-0">
          <ListFilter className="size-4" aria-hidden />
          Filters
          {activeFilters > 0 && (
            <span aria-label={`${activeFilters} active`} className="rounded-full bg-primary px-1.5 text-xs text-primary-foreground">
              {activeFilters}
            </span>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="grid w-80 max-w-[calc(100vw-2rem)] gap-3">
        {filters}
        {filtersTrailing}
        {filterChips}
        {activeFilters > 0 && onClearFilters && !filterChips && (
          <Button variant="ghost" size="sm" onClick={onClearFilters}>
            Clear filters
          </Button>
        )}
      </PopoverContent>
    </Popover>
  );
  return (
    <>
      <header className={`${tabs || hasFilters ? 'mb-3' : 'mb-6'} flex flex-wrap items-start justify-between gap-3`}>
        <div className="grid min-w-0 gap-1">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold">{title}</h1>
            {help && <HelpTip id={help} label={typeof title === 'string' ? title : undefined} />}
          </div>
          {children}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </header>
      {tabs && (
        <div className={`${hasFilters && wide ? 'mb-3' : 'mb-6'} flex items-end justify-between gap-3 border-b border-border`}>
          <nav aria-label={tabsLabel} className="flex min-w-0 gap-6 overflow-x-auto">
            {tabs}
          </nav>
          {filterSlot}
        </div>
      )}
      {hasFilters && wide && (
        <div className="mb-6">
          <FilterToolbar activeFilters={activeFilters} onClear={onClearFilters} trailing={filtersTrailing}>
            {filters}
          </FilterToolbar>
        </div>
      )}
      {!tabs && filterSlot && <div className="mb-6 flex justify-end">{filterSlot}</div>}
    </>
  );
}
