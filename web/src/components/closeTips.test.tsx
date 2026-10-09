import userEvent from '@testing-library/user-event';
import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { TooltipProvider } from '@/components/ui/tooltip';
import { FilterChips } from './FilterChips';
import { ListInput } from './ListInput';
import { MultiCombobox } from './MultiCombobox';
import { SavedViews } from './SavedViews';

const wrap = (ui: React.ReactNode) => render(<TooltipProvider>{ui}</TooltipProvider>);

async function expectTip(name: string) {
  const user = userEvent.setup();
  await user.hover(screen.getByRole('button', { name }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent(name);
}

it('dialog close X has a tooltip and none auto-opens on initial focus', async () => {
  wrap(
    <Dialog open>
      <DialogContent>
        <DialogTitle>T</DialogTitle>
        <DialogDescription>D</DialogDescription>
      </DialogContent>
    </Dialog>,
  );
  await new Promise((r) => setTimeout(r, 50));
  expect(screen.queryByRole('tooltip')).toBeNull();
  await expectTip('Close');
});

it('sheet close X has a tooltip and none auto-opens on initial focus', async () => {
  wrap(
    <Sheet open>
      <SheetContent>
        <SheetTitle>T</SheetTitle>
        <SheetDescription>D</SheetDescription>
      </SheetContent>
    </Sheet>,
  );
  await new Promise((r) => setTimeout(r, 50));
  expect(screen.queryByRole('tooltip')).toBeNull();
  await expectTip('Close');
});

it('ListInput chip remove has a tooltip', async () => {
  wrap(<ListInput aria-label="L" value={['a.example']} onChange={() => {}} />);
  await expectTip('Remove a.example');
});

it('MultiCombobox chip remove has a tooltip', async () => {
  wrap(<MultiCombobox aria-label="M" value={['a']} onChange={() => {}} options={[{ value: 'a', label: 'Alpha' }]} placeholder="p" emptyText="e" />);
  await expectTip('Remove Alpha');
});

it('FilterChips remove has a tooltip', async () => {
  wrap(<FilterChips chips={[{ key: 'q', label: 'q: x' }]} onRemove={() => {}} onClear={() => {}} />);
  await expectTip('Remove filter q: x');
});

it('SavedViews delete has a tooltip', async () => {
  localStorage.setItem('cf-views-tipview', JSON.stringify([{ name: 'v1', search: { q: 'x' } }]));
  wrap(<SavedViews list="tipview" current={{}} onApply={() => {}} />);
  await expectTip('Delete view v1');
});
