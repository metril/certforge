import type { KeyboardEvent, MouseEvent } from 'react';
import { createColumnHelper, flexRender, tableFeatures, useTable, type CellData, type ColumnDef, type RowData, type TableFeatures } from '@tanstack/react-table';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import type { HelpKey } from '@/lib/help';
import { cn } from '@/lib/utils';
import { HelpTip } from './HelpTip';
import { HintLabel } from './HintLabel';

// Core-only table (sorting is server-side), so no optional features are enabled.
const features = tableFeatures({});
type Features = typeof features;

/** Typed column helper bound to this table's (empty) feature set. */
export const columnHelper = <T extends RowData>() => createColumnHelper<Features, T>();

declare module '@tanstack/react-table' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TFeatures extends TableFeatures, TData extends RowData, TValue extends CellData = CellData> {
    sortKey?: string;
    help?: HelpKey;
    /** Help copy shown as a tooltip on the header label (no icon). */
    hint?: HelpKey;
    className?: string;
  }
}

type Props<T extends RowData> = {
  data: T[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  columns: ColumnDef<Features, T, any>[];
  getRowId: (row: T) => string;
  ariaLabel: string;
  sort?: string;
  onSort?: (sort: string) => void;
  selected?: ReadonlySet<string>;
  onRowClick?: (id: string, e: MouseEvent | KeyboardEvent) => void;
  onRowOpen?: (id: string) => void;
  /** Renders this many placeholder rows (real header, no interaction)
   * instead of `data`'s rows, for a first-load fetch — a loading table
   * shape instead of a layout-jumping bare paragraph (review fix round 1). */
  skeletonRows?: number;
};

export function DataTable<T extends RowData>({ data, columns, getRowId, ariaLabel, sort, onSort, selected, onRowClick, onRowOpen, skeletonRows }: Props<T>) {
  const table = useTable<Features, T>({ features, data, columns, getRowId: (r) => getRowId(r) });
  return (
    <Table aria-label={ariaLabel} aria-busy={!!skeletonRows} className="table-fixed">
      <TableHeader>
        {table.getHeaderGroups().map((hg) => (
          <TableRow key={hg.id}>
            {hg.headers.map((h) => {
              const meta = h.column.columnDef.meta;
              const key = meta?.sortKey;
              const dir = key && sort === key ? 'ascending' : key && sort === `-${key}` ? 'descending' : undefined;
              const label = flexRender(h.column.columnDef.header, h.getContext());
              return (
                <TableHead key={h.id} aria-sort={key ? (dir ?? 'none') : undefined} className={cn('overflow-x-clip', meta?.className)}>
                  <span className="inline-flex items-center gap-1">
                    {key && onSort ? (
                      <button type="button" className="inline-flex items-center gap-1 hover:text-ink" onClick={() => onSort(dir === 'ascending' ? `-${key}` : key)}>
                        {meta?.hint ? <HintLabel id={meta.hint} focusable={false}>{label}</HintLabel> : label}
                        {dir === 'ascending' ? <ArrowUp className="size-3.5" aria-hidden /> : dir === 'descending' ? <ArrowDown className="size-3.5" aria-hidden /> : <ArrowUpDown className="size-3.5 opacity-40" aria-hidden />}
                      </button>
                    ) : meta?.hint ? (
                      <HintLabel id={meta.hint}>{label}</HintLabel>
                    ) : (
                      label
                    )}
                    {meta?.help && <HelpTip id={meta.help} />}
                  </span>
                </TableHead>
              );
            })}
          </TableRow>
        ))}
      </TableHeader>
      <TableBody>
        {skeletonRows
          ? Array.from({ length: skeletonRows }).map((_, i) => (
              <TableRow key={`skeleton-${i}`} aria-hidden className="h-9 rounded-none">
                {columns.map((c, j) => (
                  <TableCell key={j} className={cn('overflow-x-clip', c.meta?.className)}>
                    <div className="h-3 w-3/4 animate-pulse rounded-sm bg-subtle" />
                  </TableCell>
                ))}
              </TableRow>
            ))
          : table.getRowModel().rows.map((row) => {
              const isSel = selected?.has(row.id) ?? false;
              return (
                <TableRow
                  key={row.id}
                  aria-current={isSel ? 'true' : undefined}
                  tabIndex={onRowClick || onRowOpen ? 0 : undefined}
                  className={cn('h-9 rounded-none', (onRowClick || onRowOpen) && 'cursor-pointer', isSel && 'bg-primary/10 hover:bg-primary/15')}
                  onMouseDown={(e) => e.shiftKey && e.preventDefault()}
                  onClick={(e) => {
                    if (onRowClick) return onRowClick(row.id, e);
                    // Open-only table: a click on the row opens it, but not one on an inner control or while selecting text.
                    const inner = (e.target as HTMLElement).closest('a,button,input,select,textarea,[role="button"]');
                    if (inner && e.currentTarget.contains(inner)) return;
                    if (window.getSelection()?.toString()) return;
                    onRowOpen?.(row.id);
                  }}
                  onKeyDown={(e) => {
                    if (e.target !== e.currentTarget) return;
                    if (e.key === ' ') {
                      e.preventDefault();
                      onRowClick?.(row.id, e);
                    } else if (e.key === 'Enter') onRowOpen?.(row.id);
                  }}
                >
                  {row.getAllCells().map((c) => (
                    // Fix round 1 (review): the sticky Name cell's own
                    // opaque `bg-panel` (needed so scrolled-under cells
                    // don't show through it) otherwise paints over the
                    // row's `bg-primary/10` selected tint right where the
                    // sticky column sits. `cn` resolves the conflicting
                    // `bg-*` utility (tailwind-merge), so the tint wins once
                    // selected, on every cell (a no-op visually on
                    // non-sticky cells, which were already showing the
                    // row's own background through their default
                    // transparent one).
                    <TableCell key={c.id} className={cn('overflow-x-clip', c.column.columnDef.meta?.className, isSel && 'bg-primary/10')}>
                      {flexRender(c.column.columnDef.cell, c.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              );
            })}
      </TableBody>
    </Table>
  );
}
