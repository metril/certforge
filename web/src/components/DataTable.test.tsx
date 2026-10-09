import userEvent from '@testing-library/user-event';
import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { columnHelper, DataTable } from './DataTable';

const col = columnHelper<{ id: string; name: string }>();

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

it('marks only the selected row aria-current', () => {
  render(<DataTable data={rows} columns={cols} getRowId={(r) => r.id} ariaLabel="T" selected={new Set(['2'])} onRowClick={() => {}} />);
  expect(screen.getByRole('row', { name: 'a' })).not.toHaveAttribute('aria-current');
  expect(screen.getByRole('row', { name: 'b' })).toHaveAttribute('aria-current', 'true');
  for (const r of screen.getAllByRole('row').slice(1)) expect(r).not.toHaveAttribute('aria-selected');
});

it('makes rows focusable and opens on Enter when only onRowOpen is passed', async () => {
  const open = vi.fn();
  const user = userEvent.setup();
  render(<DataTable data={rows} columns={cols} getRowId={(r) => r.id} ariaLabel="T" onRowOpen={open} />);
  screen.getByRole('row', { name: 'a' }).focus();
  await user.keyboard('{Enter}');
  expect(open).toHaveBeenCalledWith('1');
});

it('with only onRowOpen, a row click and Enter open it, but a click on an inner link does not', async () => {
  const open = vi.fn();
  const user = userEvent.setup();
  const linkCols = [col.display({ id: 'n', header: 'Name', cell: ({ row }) => <a href="#x">{row.original.name}</a> })];
  render(<DataTable data={rows} columns={linkCols} getRowId={(r) => r.id} ariaLabel="T" onRowOpen={open} />);
  await user.click(screen.getByRole('link', { name: 'a' }));
  expect(open).not.toHaveBeenCalled();
  await user.click(screen.getByRole('row', { name: 'a' }));
  expect(open).toHaveBeenCalledWith('1');
  screen.getByRole('row', { name: 'b' }).focus();
  await user.keyboard('{Enter}');
  expect(open).toHaveBeenCalledWith('2');
});
