import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Digest } from './Digest';

const v = 'ab'.repeat(32);

it('shows the head and an 8-character tail without a title', () => {
  render(<Digest value={v} label="installed digest" />);
  const btn = screen.getByRole('button', { name: 'Show installed digest' });
  expect(btn).not.toHaveAttribute('title');
  const [head, tail] = Array.from(btn.querySelectorAll('span'));
  expect(head!.textContent).toBe(v.slice(0, -8));
  expect(tail!.textContent).toBe(v.slice(-8));
});

const ui = (
  <TooltipProvider>
    <Digest value={v} label="installed digest" />
  </TooltipProvider>
);

it('opens the full digest on click', async () => {
  const user = userEvent.setup();
  render(ui);
  await user.click(screen.getByRole('button', { name: 'Show installed digest' }));
  expect(screen.getByRole('button', { name: 'Copy installed digest' })).toBeInTheDocument();
});

it('opens the full digest on Enter', async () => {
  const user = userEvent.setup();
  render(ui);
  screen.getByRole('button', { name: 'Show installed digest' }).focus();
  await user.keyboard('{Enter}');
  expect(screen.getByRole('button', { name: 'Copy installed digest' })).toBeInTheDocument();
});

it('renders a dash for no digest', () => {
  render(<Digest value={null} label="installed digest" />);
  expect(screen.getByText('–')).toBeInTheDocument();
  expect(screen.queryByRole('button')).toBeNull();
});
