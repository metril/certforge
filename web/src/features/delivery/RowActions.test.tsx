import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { RowActions } from './RowActions';

it.each([
  { canWrite: false, grantCount: 0 },
  { canWrite: true, grantCount: 2 },
])('disabled Delete has a single tab-stop wrapper ($canWrite, $grantCount)', ({ canWrite, grantCount }) => {
  render(
    <TooltipProvider>
      <RowActions name="x" grantCount={grantCount} canWrite={canWrite} onOpen={() => {}} onDelete={() => {}} />
    </TooltipProvider>,
  );
  const btn = screen.getByRole('button', { name: 'Delete x' });
  expect(btn).toBeDisabled();
  expect(btn.parentElement).toHaveAttribute('tabindex', '0');
  expect(btn.parentElement!.parentElement).not.toHaveAttribute('tabindex');
});
