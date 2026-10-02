import { screen, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { renderUI } from '@/test/render';
import { FilterField, FilterToolbar } from './FilterToolbar';

it('FilterToolbar is a labelled search region with Clear only when filters are active', async () => {
  const onClear = vi.fn();
  const { user } = renderUI(
    <FilterToolbar activeFilters={2} onClear={onClear} trailing={<span>Views</span>}>
      <FilterField label="Search">
        <input aria-label="Search things" />
      </FilterField>
    </FilterToolbar>,
  );
  expect(screen.getByRole('search', { name: 'Filters' })).toBeInTheDocument();
  expect(screen.getByText('Views')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Clear filters' }));
  expect(onClear).toHaveBeenCalledTimes(1);
});

it('FilterToolbar hides Clear when no filter is active', () => {
  renderUI(
    <FilterToolbar activeFilters={0} onClear={vi.fn()}>
      <span>x</span>
    </FilterToolbar>,
  );
  expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument();
});

it('FilterField shows its label beside the control and a HelpTip when given help', () => {
  renderUI(
    <FilterField label="Severity" help="event.severity">
      <input aria-label="Sev" />
    </FilterField>,
  );
  expect(screen.getByText('Severity')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Help' })).toBeInTheDocument();
  expect(screen.getByLabelText('Sev')).toBeInTheDocument();
});

it('FilterField associates its label with the control group', () => {
  renderUI(
    <FilterField label="Severity">
      <input aria-label="Sev" />
    </FilterField>,
  );
  expect(within(screen.getByRole('group', { name: 'Severity' })).getByLabelText('Sev')).toBeInTheDocument();
});
