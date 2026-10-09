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
  expect(screen.getByRole('button', { name: 'Delete x' })).toHaveAttribute('aria-disabled', 'true');
  await user.hover(screen.getByRole('button', { name: 'Delete x' }));
  expect((await screen.findAllByText('Needs the write permission')).length).toBeGreaterThan(0);
});

it('aria-disabled click does not fire onClick, bubble, or submit, and keeps identity and focus', async () => {
  const user = userEvent.setup();
  const onClick = vi.fn();
  const onParent = vi.fn();
  const onSubmit = vi.fn((e: React.FormEvent) => e.preventDefault());
  const ui = (disabled: boolean) => (
    <TooltipProvider>
      <form onSubmit={onSubmit} onClick={onParent}>
        <IconButton label="Go" type="submit" disabled={disabled} onClick={onClick}>
          <span>x</span>
        </IconButton>
      </form>
    </TooltipProvider>
  );
  const { rerender } = render(ui(true));
  const btn = screen.getByRole('button', { name: 'Go' });
  expect(btn).toHaveAttribute('aria-disabled', 'true');
  await user.click(btn);
  expect(onClick).not.toHaveBeenCalled();
  expect(onParent).not.toHaveBeenCalled();
  expect(onSubmit).not.toHaveBeenCalled();
  btn.focus();
  rerender(ui(false));
  expect(screen.getByRole('button', { name: 'Go' })).toBe(btn);
  expect(btn).toHaveFocus();
});
