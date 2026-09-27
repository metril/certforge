import { useState } from 'react';
import { screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { renderUI } from '@/test/render';
import { MultiCombobox } from './MultiCombobox';

function Harness() {
  const [v, setV] = useState<string[]>([]);
  return (
    <MultiCombobox
      aria-label="Certificates"
      value={v}
      onChange={setV}
      options={[{ value: 'c-1', label: 'www' }, { value: 'c-2', label: 'api', keywords: ['api.example.com'] }, { value: 'c-3', label: 'mail' }]}
      placeholder="Pick certificates"
      emptyText="No certificate matches."
    />
  );
}

it('picks several items in order, shows them as chips and removes one', async () => {
  const { user } = renderUI(<Harness />);
  await user.click(screen.getByRole('combobox', { name: 'Certificates' }));
  await user.click(screen.getByRole('option', { name: 'mail' }));
  await user.type(screen.getByPlaceholderText('Search'), 'api.example');
  await user.click(screen.getByRole('option', { name: 'api' }));
  await user.keyboard('{Escape}');
  const chips = screen.getByRole('list', { name: 'Selected certificates' });
  expect(within(chips).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['mail', 'api']);
  expect(screen.getByRole('combobox', { name: 'Certificates' })).toHaveTextContent('2 selected');
  await user.click(screen.getByRole('button', { name: 'Remove mail' }));
  expect(within(chips).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['api']);
});

function CappedHarness() {
  const [v, setV] = useState<string[]>(['c-1']);
  return (
    <MultiCombobox
      aria-label="Certificates"
      value={v}
      onChange={setV}
      options={[
        { value: 'c-1', label: 'www' },
        { value: 'c-2', label: 'api', disabled: true, hint: 'Up to 10' },
      ]}
      placeholder="Pick certificates"
      emptyText="No certificate matches."
    />
  );
}

// B4: a disabled option (the 11th, once 10 are already picked) shows its
// hint as a tooltip and cannot be toggled.
it('a disabled option shows its hint and cannot be picked', async () => {
  const { user } = renderUI(<CappedHarness />);
  await user.click(screen.getByRole('combobox', { name: 'Certificates' }));
  const disabledOption = screen.getByRole('option', { name: 'api' });
  await user.hover(disabledOption);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Up to 10');
  await user.click(disabledOption);
  expect(screen.getByRole('combobox', { name: 'Certificates' })).toHaveTextContent('1 selected');
});
