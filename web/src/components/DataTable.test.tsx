import { render, screen } from '@testing-library/react';
import { createColumnHelper } from '@tanstack/react-table';
import { expect, it } from 'vitest';
import { DataTable } from './DataTable';

const col = createColumnHelper<{ id: string; name: string }>();

it('clips every header and body cell so content cannot widen the fixed layout', () => {
  render(<DataTable data={[{ id: '1', name: 'a' }]} columns={[col.display({ id: 'n', header: 'Name', cell: ({ row }) => row.original.name })]} getRowId={(r) => r.id} ariaLabel="T" />);
  expect(screen.getByRole('table')).toHaveClass('table-fixed');
  for (const cell of [screen.getByRole('columnheader', { name: 'Name' }), screen.getByRole('cell', { name: 'a' })]) expect(cell).toHaveClass('overflow-x-clip');
});

const rows = [
  { id: '1', name: 'a' },
  { id: '2', name: 'b' },
];
const cols = [col.display({ id: 'n', header: 'Name', cell: ({ row }) => row.original.name })];

it('marks aria-selected on the rows of a table with a selection, true only on the selected one', () => {
  render(<DataTable data={rows} columns={cols} getRowId={(r) => r.id} ariaLabel="T" selected={new Set(['2'])} onRowClick={() => {}} />);
  expect(screen.getByRole('row', { name: 'a' })).toHaveAttribute('aria-selected', 'false');
  expect(screen.getByRole('row', { name: 'b' })).toHaveAttribute('aria-selected', 'true');
});

it('omits aria-selected on a clickable table that has no selection', () => {
  render(<DataTable data={rows} columns={cols} getRowId={(r) => r.id} ariaLabel="T" onRowClick={() => {}} />);
  for (const r of screen.getAllByRole('row').slice(1)) expect(r).not.toHaveAttribute('aria-selected');
});
