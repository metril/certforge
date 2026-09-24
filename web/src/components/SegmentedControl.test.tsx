import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { SegmentedControl } from './SegmentedControl';

it('selects an option and never deselects to empty', async () => {
  const onChange = vi.fn();
  const user = userEvent.setup();
  render(
    <TooltipProvider>
      <SegmentedControl
        aria-label="Mode"
        value="days"
        onChange={onChange}
        options={[
          { value: 'days', label: 'Days' },
          { value: 'percent', label: 'Percent' },
          { value: 'later', label: 'Later', disabled: true, hint: 'Available in a later phase' },
        ]}
      />
    </TooltipProvider>,
  );
  expect(screen.getByRole('radio', { name: 'Days' })).toHaveAttribute('aria-checked', 'true');
  await user.click(screen.getByRole('radio', { name: 'Days' }));
  expect(onChange).not.toHaveBeenCalled();
  await user.click(screen.getByRole('radio', { name: 'Percent' }));
  expect(onChange).toHaveBeenCalledWith('percent');
  expect(screen.getByRole('radio', { name: 'Later' })).toBeDisabled();
});
