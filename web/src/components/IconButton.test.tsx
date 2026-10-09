import userEvent from '@testing-library/user-event';
import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { IconButton } from './IconButton';

const wrap = (ui: React.ReactNode) => render(<TooltipProvider>{ui}</TooltipProvider>);

it('uses label as aria-label and tooltip text, and forwards clicks and refs', async () => {
  const onClick = vi.fn();
  const ref = { current: null as HTMLButtonElement | null };
  const user = userEvent.setup();
  wrap(
    <IconButton ref={ref} label="Copy thing" onClick={onClick}>
      <span>x</span>
    </IconButton>,
  );
  const btn = screen.getByRole('button', { name: 'Copy thing' });
  expect(ref.current).toBe(btn);
  await user.hover(btn);
  expect((await screen.findAllByText('Copy thing')).length).toBeGreaterThan(0);
  await user.click(btn);
  expect(onClick).toHaveBeenCalled();
});

it('when disabled with a tip, the tip (denial reason) shows on hover and the button stays disabled', async () => {
  const user = userEvent.setup();
  wrap(
    <IconButton label="Delete x" tip="Needs the write permission" disabled>
      <span>x</span>
    </IconButton>,
  );
  expect(screen.getByRole('button', { name: 'Delete x' })).toBeDisabled();
  await user.hover(screen.getByRole('button', { name: 'Delete x' }).parentElement!);
  expect((await screen.findAllByText('Needs the write permission')).length).toBeGreaterThan(0);
});
