import { useState } from 'react';
import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { renderUI } from '@/test/render';
import { InheritableField } from './InheritableField';

function H() {
  const [v, setV] = useState<string | null>(null);
  return (
    <>
      <InheritableField<string>
        id="kt"
        label="Key type"
        value={v}
        inherited={{ value: 'ec256', source: 'global' }}
        chain={[{ level: 'Global', value: 'EC P-256' }]}
        initial="rsa2048"
        display={(x) => <span>{x}</span>}
        editor={(x, set) => <input aria-label="editor" value={x} onChange={(e) => set(e.target.value)} />}
        onChange={setV}
      />
      <output data-testid="v">{String(v)}</output>
    </>
  );
}

it('shows the inherited value with its source, overrides, and resets to null', async () => {
  const { user } = renderUI(<H />);
  expect(screen.getByText('ec256')).toBeInTheDocument();
  await user.hover(screen.getByRole('button', { name: 'Global' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Global: EC P-256');
  await user.click(screen.getByRole('switch', { name: 'Override Key type' }));
  expect(screen.getByLabelText('editor')).toHaveValue('ec256');
  expect(screen.getByTestId('v')).toHaveTextContent('ec256');
  await user.click(screen.getByRole('button', { name: 'Reset to inherited' }));
  expect(screen.getByTestId('v')).toHaveTextContent('null');
  expect(screen.getByRole('button', { name: 'Global' })).toBeInTheDocument();
});

it('shows a 422 mapped to the field next to its editor', async () => {
  function WithError() {
    const [v, setV] = useState<string | null>('ec256');
    return (
      <InheritableField<string>
        id="kt"
        label="Key type"
        value={v}
        inherited={{ value: null, source: 'default' }}
        initial="rsa2048"
        display={(x) => <span>{x}</span>}
        editor={(x, set) => <input aria-label="editor" value={x} onChange={(e) => set(e.target.value)} />}
        onChange={setV}
        error="no such CA in this org"
      />
    );
  }
  renderUI(<WithError />);
  expect(await screen.findByRole('alert')).toHaveTextContent('no such CA in this org');
});

it('disables Override with a reason, but still allows resetting an already-overridden field', async () => {
  function WithDisabled() {
    const [v, setV] = useState<string | null>('ec256');
    return (
      <InheritableField<string>
        id="kt"
        label="Key type"
        value={v}
        inherited={{ value: null, source: 'default' }}
        initial="rsa2048"
        display={(x) => <span>{x}</span>}
        editor={(x, set) => <input aria-label="editor" value={x} onChange={(e) => set(e.target.value)} />}
        onChange={setV}
        overrideDisabled="No CAs yet"
      />
    );
  }
  const { user } = renderUI(<WithDisabled />);
  expect(screen.getByRole('switch', { name: 'Override Key type' })).not.toBeDisabled();
  expect(screen.getByLabelText('editor')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Reset to inherited' }));
  expect(screen.getByRole('switch', { name: 'Override Key type' })).toBeDisabled();
  expect(screen.getByText('No CAs yet')).toBeInTheDocument();
});

it('shows a pending state instead of the stale inherited value after a reset that has not saved yet', () => {
  renderUI(
    <InheritableField<string>
      id="kt"
      label="Key type"
      value={null}
      inherited={{ value: 'ec256', source: 'org' }}
      initial="rsa2048"
      display={(x) => <span>{x}</span>}
      editor={(x, set) => <input aria-label="editor" value={x} onChange={(e) => set(e.target.value)} />}
      onChange={() => {}}
      pending
    />,
  );
  expect(screen.getByText('Pending')).toBeInTheDocument();
  expect(screen.getByText('Inherited after save')).toBeInTheDocument();
  expect(screen.queryByText('ec256')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Org' })).toBeNull();
});
