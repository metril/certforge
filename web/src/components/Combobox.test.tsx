import { useState } from 'react';
import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { renderUI } from '@/test/render';
import { Combobox } from './Combobox';

function Harness() {
  const [v, setV] = useState<string | undefined>(undefined);
  return (
    <Combobox
      aria-label="Certificate"
      value={v}
      onChange={setV}
      options={[
        { value: 'c-1', label: 'www' },
        { value: 'c-2', label: 'api', disabled: true, hint: 'Not available' },
      ]}
      placeholder="Pick a certificate"
      emptyText="No certificate matches."
    />
  );
}

it('has no clear button by default, and shows one only when clearable', () => {
  const opts = [{ value: 'a', label: 'Alpha' }];
  const props = { 'aria-label': 'X', value: 'a', onChange: () => {}, options: opts, placeholder: 'p', emptyText: 'e' };
  const first = renderUI(<Combobox {...props} />);
  expect(screen.queryByRole('button', { name: 'Clear X' })).toBeNull();
  first.unmount();
  renderUI(<Combobox {...props} clearable />);
  expect(screen.getByRole('button', { name: 'Clear X' })).toBeInTheDocument();
});

// Review fix round 1 (B4 shared with MultiCombobox): a disabled option shows
// its hint as a tooltip and cannot be picked.
it('a disabled option shows its hint and cannot be picked', async () => {
  const { user } = renderUI(<Harness />);
  await user.click(screen.getByRole('combobox', { name: 'Certificate' }));
  const disabledOption = screen.getByRole('option', { name: 'api' });
  await user.hover(disabledOption);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Not available');
  await user.click(disabledOption);
  expect(screen.getByRole('combobox', { name: 'Certificate' })).toHaveTextContent('Pick a certificate');
});
