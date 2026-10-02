import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { Card } from '@/components/Card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './table';

const table = (
  <Table aria-label="T">
    <TableHeader>
      <TableRow>
        <TableHead>Name</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow>
        <TableCell>a</TableCell>
      </TableRow>
    </TableBody>
  </Table>
);

const container = () => screen.getByRole('table').parentElement!;

it('frames itself on the canvas with a subtle header', () => {
  render(table);
  const cls = container().className;
  for (const c of ['rounded-md', 'border', 'border-border', 'bg-panel', 'overflow-x-auto']) expect(cls).toContain(c);
  expect(screen.getByRole('table').querySelector('thead')!.className).toContain('bg-subtle');
  expect(screen.getByRole('columnheader', { name: 'Name' }).className).toContain('text-ink-muted');
  expect(screen.getAllByRole('row')[1]!.className).toContain('hover:bg-subtle/60');
});

it('drops its own frame inside a Card', () => {
  render(<Card>{table}</Card>);
  const cls = container().className;
  for (const c of ['rounded-md', 'border-border', 'bg-panel']) expect(cls).not.toContain(c);
  expect(cls).toContain('overflow-x-auto');
});
