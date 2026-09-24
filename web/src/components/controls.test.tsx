import { useState } from 'react';
import { screen, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { UNCHANGED } from '@/api/types';
import { renderUI } from '@/test/render';
import { ChipSet } from './ChipSet';
import { Combobox } from './Combobox';
import { ConfirmDestructive } from './ConfirmDestructive';
import { CopyField } from './CopyField';
import { ListInput } from './ListInput';
import { SecretInput } from './SecretInput';
import { SwitchField } from './SwitchField';

function SecretHarness({ stored }: { stored: boolean }) {
  const [v, setV] = useState<string | undefined>(stored ? UNCHANGED : undefined);
  return (
    <>
      <SecretInput id="token" stored={stored} value={v} onChange={setV} />
      <output data-testid="value">{String(v)}</output>
    </>
  );
}

it('secret: replace, type, then keep stored sends the sentinel', async () => {
  const { user } = renderUI(<SecretHarness stored />);
  expect(screen.getByText('Stored')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Replace' }));
  await user.type(screen.getByLabelText('New value'), 'new-token');
  expect(screen.getByTestId('value')).toHaveTextContent('new-token');
  await user.click(screen.getByRole('button', { name: 'Keep stored' }));
  expect(screen.getByTestId('value')).toHaveTextContent(UNCHANGED);
  expect(screen.getByText('Stored')).toBeInTheDocument();
});

it('secret: clearing the replacement keeps the stored value, never an empty string', async () => {
  const { user } = renderUI(<SecretHarness stored />);
  await user.click(screen.getByRole('button', { name: 'Replace' }));
  const input = screen.getByLabelText('New value');
  await user.type(input, 'x');
  await user.clear(input);
  expect(screen.getByTestId('value')).toHaveTextContent(UNCHANGED);
});

it('secret: new secret is a plain password input; empty is undefined', async () => {
  const { user } = renderUI(<SecretHarness stored={false} />);
  const input = screen.getByLabelText('New value');
  expect(input).toHaveAttribute('type', 'password');
  await user.type(input, 'a');
  await user.clear(input);
  expect(screen.getByTestId('value')).toHaveTextContent('undefined');
});

it('switch shows its state text on the right', async () => {
  function H() {
    const [on, setOn] = useState(false);
    return <SwitchField id="reuse" label="Reuse key" checked={on} onCheckedChange={setOn} onText="Keep key" offText="New key" />;
  }
  const { user } = renderUI(<H />);
  expect(screen.getByText('New key')).toBeInTheDocument();
  await user.click(screen.getByRole('switch', { name: 'Reuse key' }));
  expect(screen.getByText('Keep key')).toBeInTheDocument();
});

it('chips toggle with aria-pressed and a check glyph', async () => {
  const onChange = vi.fn();
  const { user } = renderUI(
    <ChipSet aria-label="Parts" value={['fullchain']} onChange={onChange} options={[{ value: 'cert', label: 'cert' }, { value: 'fullchain', label: 'fullchain' }]} />,
  );
  expect(screen.getByRole('button', { name: 'fullchain' })).toHaveAttribute('aria-pressed', 'true');
  await user.click(screen.getByRole('button', { name: 'cert' }));
  expect(onChange).toHaveBeenCalledWith(['fullchain', 'cert']);
});

it('combobox searches and selects', async () => {
  const onChange = vi.fn();
  const { user } = renderUI(
    <Combobox aria-label="CA" value={undefined} onChange={onChange} placeholder="Choose CA" emptyText="No CA" options={[{ value: 'a', label: "Let's Encrypt" }, { value: 'b', label: 'ZeroSSL' }]} />,
  );
  await user.click(screen.getByRole('combobox', { name: 'CA' }));
  await user.type(screen.getByPlaceholderText('Search'), 'zero');
  await user.click(screen.getByRole('option', { name: 'ZeroSSL' }));
  expect(onChange).toHaveBeenCalledWith('b');
});

it('list input adds on Enter and comma, dedupes, removes', async () => {
  function H() {
    const [v, setV] = useState<string[]>([]);
    return <ListInput aria-label="Resolvers" value={v} onChange={setV} />;
  }
  const { user } = renderUI(<H />);
  const input = screen.getByLabelText('Resolvers');
  await user.type(input, '1.1.1.1{Enter}8.8.8.8,1.1.1.1{Enter}');
  expect(screen.getAllByRole('button', { name: /^Remove / })).toHaveLength(2);
  await user.click(screen.getByRole('button', { name: 'Remove 1.1.1.1' }));
  expect(screen.queryByText('1.1.1.1')).toBeNull();
});

it('copy field writes to the clipboard', async () => {
  const { user } = renderUI(<CopyField value="ab:cd" label="fingerprint" />);
  await user.click(screen.getByRole('button', { name: 'Copy fingerprint' }));
  expect(await navigator.clipboard.readText()).toBe('ab:cd');
});

it('confirm destructive requires the exact text and shows server errors inline', async () => {
  const onConfirm = vi.fn().mockRejectedValue(new Error('CA is used by 2 certificates'));
  const { user } = renderUI(
    <ConfirmDestructive open onOpenChange={() => {}} title="Delete CA" consequence="Certificates using it stop renewing." confirmText="Let's Encrypt" actionLabel="Delete CA" onConfirm={onConfirm} />,
  );
  const dialog = screen.getByRole('dialog');
  const action = within(dialog).getByRole('button', { name: 'Delete CA' });
  expect(action).toBeDisabled();
  await user.type(within(dialog).getByRole('textbox'), "Let's Encrypt");
  await user.click(action);
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('CA is used by 2 certificates');
});
