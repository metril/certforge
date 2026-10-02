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
