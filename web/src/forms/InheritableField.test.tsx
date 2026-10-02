import { useState } from 'react';
import { screen, waitFor, within } from '@testing-library/react';
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
        chain={[
          { level: 'global', value: 'EC P-256' },
        ]}
        links={{ global: '/settings/issuance-defaults?scope=global', org: '/settings/issuance-defaults?scope=org' }}
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
  await user.click(screen.getByRole('button', { name: 'Global' }));
  await waitFor(() => expect(document.querySelector('[data-slot="popover-content"]')).toHaveTextContent('Global: EC P-256'));
  await user.keyboard('{Escape}');
  await user.click(screen.getByRole('switch', { name: 'Override Key type' }));
  expect(screen.getByLabelText('editor')).toHaveValue('ec256');
  expect(screen.getByTestId('v')).toHaveTextContent('ec256');
  await user.click(screen.getByRole('button', { name: 'Use Global value' }));
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
  await user.click(screen.getByRole('button', { name: 'Use Global value' }));
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
  expect(screen.queryByRole('button', { name: 'Organization' })).toBeNull();
});

it('shows one source badge whose popover lists each level with the one in effect emphasised and linked editors, plus Using/Set here state text', async () => {
  const { user } = renderUI(<H />);
  expect(screen.queryByLabelText('Defaults chain')).toBeNull();
  expect(screen.getAllByRole('button', { name: 'Global' })).toHaveLength(1);
  await user.click(screen.getByRole('button', { name: 'Global' }));
  const pop = within(document.querySelector('[data-slot="popover-content"]') as HTMLElement);
  const el = document.querySelector('[data-slot="popover-content"]');
  expect(el).toHaveTextContent('Organization: set per organization');
  expect(el?.querySelector('[aria-current="true"]')).toHaveTextContent('Global: EC P-256');
  expect(pop.getByRole('link', { name: 'Organization' })).toHaveAttribute('href', '/settings/issuance-defaults?scope=org');
  await user.keyboard('{Escape}');
  expect(screen.getByText('Using Global:')).toBeInTheDocument();
  await user.click(screen.getByRole('switch', { name: 'Override Key type' }));
  expect(screen.getByText('Set here')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Use Global value' })).toBeInTheDocument();
});

it('shows an unset-everywhere field as a short state with no source badge', () => {
  renderUI(
    <InheritableField<string>
      id="c"
      label="Certificate authority"
      value={null}
      inherited={{ value: null, source: 'default' }}
      unset={{ label: 'Not set', tone: 'expiring', tip: 'Issuance fails until a certificate authority is set.' }}
      initial="x"
      display={(x) => <span>{x}</span>}
      editor={() => null}
      onChange={() => {}}
    />,
  );
  expect(screen.getByText('Not set')).toBeInTheDocument();
});

it('Global scope has no Override switch: it edits the shipped value in place and Reset appears only once it differs', async () => {
  function G() {
    const [v, setV] = useState<string | null>(null);
    return (
      <>
        <InheritableField<string>
          id="kt"
          label="Key type"
          level="global"
          value={v}
          inherited={{ value: 'ec256', source: 'default' }}
          initial="rsa2048"
          display={(x) => <span>{x}</span>}
          editor={(x, set) => <input aria-label="editor" value={x} onChange={(e) => set(e.target.value)} />}
          onChange={setV}
        />
        <output data-testid="v">{String(v)}</output>
      </>
    );
  }
  const { user } = renderUI(<G />);
  expect(screen.queryByRole('switch')).toBeNull();
  expect(screen.queryByText(/Built-in/)).toBeNull();
  expect(screen.getByLabelText('editor')).toHaveValue('ec256');
  expect(screen.queryByRole('button', { name: 'Reset' })).toBeNull();
  await user.type(screen.getByLabelText('editor'), 'x');
  expect(screen.getByTestId('v')).toHaveTextContent('ec256x');
  await user.click(screen.getByRole('button', { name: 'Reset' }));
  expect(screen.getByTestId('v')).toHaveTextContent('null');
  expect(screen.getByLabelText('editor')).toHaveValue('ec256');
});
