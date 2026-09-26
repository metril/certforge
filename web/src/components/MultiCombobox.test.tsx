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
