import { useState } from 'react';
import { screen, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { UNCHANGED } from '@/api/types';
import { renderUI } from '@/test/render';
import { Input } from '@/components/ui/input';
import { ChipSet } from './ChipSet';
import { Combobox } from './Combobox';
import { ConfirmDestructive } from './ConfirmDestructive';
import { CopyField } from './CopyField';
import { Field } from './Field';
import { ListInput } from './ListInput';
import { SecretInput } from './SecretInput';
import { SwitchField } from './SwitchField';

function SecretHarness({ stored }: { stored: boolean }) {
  const [v, setV] = useState<string | undefined>(undefined);
  return (
    <>
      <SecretInput id="token" label="Recovery token" stored={stored} value={v} onChange={setV} />
      <output data-testid="value">{String(v)}</output>
    </>
  );
}

function ToggleStoredHarness() {
  const [stored, setStored] = useState(false);
  const [v, setV] = useState<string | undefined>(undefined);
  return (
    <>
      <SecretInput id="token" label="Recovery token" stored={stored} value={v} onChange={setV} />
      <output data-testid="value">{String(v)}</output>
      <button type="button" onClick={() => setStored(true)}>
        Mark stored
      </button>
    </>
  );
}

it('secret: stored and untouched emits the sentinel on its own, even seeded undefined', () => {
  // Review round 1: a caller starting with `undefined` must not silently
  // omit the key and erase the secret on PUT.
  renderUI(<SecretHarness stored />);
  expect(screen.getByTestId('value')).toHaveTextContent(UNCHANGED);
});

it('secret: toggling stored from false to true re-enters stored mode and emits the sentinel', async () => {
  const { user } = renderUI(<ToggleStoredHarness />);
  expect(screen.queryByText('Stored')).toBeNull();
  await user.type(screen.getByLabelText('Recovery token'), 'draft');
  expect(screen.getByTestId('value')).toHaveTextContent('draft');
  await user.click(screen.getByRole('button', { name: 'Mark stored' }));
  expect(screen.getByText('Stored')).toBeInTheDocument();
  expect(screen.getByTestId('value')).toHaveTextContent(UNCHANGED);
});

it('secret: replace, type, then keep stored sends the sentinel', async () => {
  const { user } = renderUI(<SecretHarness stored />);
  expect(screen.getByText('Stored')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Replace Recovery token' }));
  await user.type(screen.getByLabelText('Recovery token'), 'new-token');
  expect(screen.getByTestId('value')).toHaveTextContent('new-token');
  await user.click(screen.getByRole('button', { name: 'Keep stored Recovery token' }));
  expect(screen.getByTestId('value')).toHaveTextContent(UNCHANGED);
  expect(screen.getByText('Stored')).toBeInTheDocument();
});

it('secret: clearing the replacement keeps the stored value, never an empty string', async () => {
  const { user } = renderUI(<SecretHarness stored />);
  await user.click(screen.getByRole('button', { name: 'Replace Recovery token' }));
  const input = screen.getByLabelText('Recovery token');
  await user.type(input, 'x');
  await user.clear(input);
  expect(screen.getByTestId('value')).toHaveTextContent(UNCHANGED);
});

it('secret: show/hide toggle flips the input type and aria-pressed; masked by default', async () => {
  const { user } = renderUI(<SecretHarness stored={false} />);
  const input = screen.getByLabelText('Recovery token');
  expect(input).toHaveAttribute('type', 'password');
  const toggle = screen.getByRole('button', { name: 'Show Recovery token' });
  expect(toggle).toHaveAttribute('aria-pressed', 'false');
  expect(toggle).toHaveAttribute('aria-controls', 'token');
  await user.click(toggle);
  expect(input).toHaveAttribute('type', 'text');
  const hide = screen.getByRole('button', { name: 'Hide Recovery token' });
  expect(hide).toHaveAttribute('aria-pressed', 'true');
  await user.click(hide);
  expect(input).toHaveAttribute('type', 'password');
});

it('secret: Keep stored then Replace comes back masked, and Stored shows no reveal button', async () => {
  const { user } = renderUI(<SecretHarness stored />);
  expect(screen.queryByRole('button', { name: /^(Show|Hide) / })).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Replace Recovery token' }));
  await user.click(screen.getByRole('button', { name: 'Show Recovery token' }));
  expect(screen.getByLabelText('Recovery token')).toHaveAttribute('type', 'text');
  await user.click(screen.getByRole('button', { name: 'Keep stored Recovery token' }));
  expect(screen.queryByRole('button', { name: /^(Show|Hide) / })).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Replace Recovery token' }));
  expect(screen.getByLabelText('Recovery token')).toHaveAttribute('type', 'password');
});

it('secret: Remove clears the stored secret with an explicit empty string, not the sentinel', async () => {
  const { user } = renderUI(<SecretHarness stored />);
  expect(screen.getByText('Stored')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Remove Recovery token' }));
  expect(screen.getByTestId('value').textContent).toBe('');
});

it('secret: Remove is only offered when the field is stored', () => {
  renderUI(<SecretHarness stored={false} />);
  expect(screen.queryByRole('button', { name: /Remove/ })).not.toBeInTheDocument();
});

it('secret: Remove, then clearing the field again keeps the empty string, not the sentinel (fix round 1, Take now #4)', async () => {
  const { user } = renderUI(<SecretHarness stored />);
  await user.click(screen.getByRole('button', { name: 'Remove Recovery token' }));
  expect(screen.getByTestId('value').textContent).toBe('');
  const input = screen.getByLabelText('Recovery token');
  await user.type(input, 'x');
  expect(screen.getByTestId('value')).toHaveTextContent('x');
  await user.clear(input);
  expect(screen.getByTestId('value').textContent).toBe('');
  expect(screen.getByTestId('value')).not.toHaveTextContent(UNCHANGED);
});

it('secret: new secret is a plain password input; empty is undefined', async () => {
  const { user } = renderUI(<SecretHarness stored={false} />);
  const input = screen.getByLabelText('Recovery token');
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
  const fullchain = screen.getByRole('button', { name: 'fullchain' });
  const cert = screen.getByRole('button', { name: 'cert' });
  expect(fullchain).toHaveAttribute('aria-pressed', 'true');
  expect(within(fullchain).getByTestId('chip-check')).toBeInTheDocument();
  expect(cert).toHaveAttribute('aria-pressed', 'false');
  expect(within(cert).queryByTestId('chip-check')).toBeNull();
  await user.click(cert);
  expect(onChange).toHaveBeenCalledWith(['fullchain', 'cert']);
});

it('chips: arrow keys move focus and space toggles the focused chip', async () => {
  const onChange = vi.fn();
  const { user } = renderUI(
    <ChipSet aria-label="Parts" value={[]} onChange={onChange} options={[{ value: 'cert', label: 'cert' }, { value: 'fullchain', label: 'fullchain' }]} />,
  );
  await user.tab();
  expect(screen.getByRole('button', { name: 'cert' })).toHaveFocus();
  await user.keyboard('{ArrowRight}');
  expect(screen.getByRole('button', { name: 'fullchain' })).toHaveFocus();
  await user.keyboard(' ');
  expect(onChange).toHaveBeenCalledWith(['fullchain']);
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

it('combobox: search matches the label, not the opaque id', async () => {
  const onChange = vi.fn();
  const { user } = renderUI(
    <Combobox
      aria-label="CA"
      value={undefined}
      onChange={onChange}
      placeholder="Choose CA"
      emptyText="No CA"
      options={[{ value: '11111111-aaaa-bbbb-cccc-222222222222', label: "Let's Encrypt" }, { value: 'b', label: 'ZeroSSL' }]}
    />,
  );
  await user.click(screen.getByRole('combobox', { name: 'CA' }));
  await user.type(screen.getByPlaceholderText('Search'), 'aaaa');
  expect(screen.getByText('No CA')).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: "Let's Encrypt" })).toBeNull();
});

it('combobox closes on Escape', async () => {
  const { user } = renderUI(
    <Combobox aria-label="CA" value={undefined} onChange={vi.fn()} placeholder="Choose CA" emptyText="No CA" options={[{ value: 'a', label: "Let's Encrypt" }]} />,
  );
  await user.click(screen.getByRole('combobox', { name: 'CA' }));
  expect(screen.getByPlaceholderText('Search')).toBeInTheDocument();
  await user.keyboard('{Escape}');
  expect(screen.queryByPlaceholderText('Search')).toBeNull();
});

it('combobox: clear action unsets an optional lookup', async () => {
  const onChange = vi.fn();
  const { user } = renderUI(
    <Combobox aria-label="CA" value="b" onChange={onChange} placeholder="Choose CA" emptyText="No CA" options={[{ value: 'a', label: "Let's Encrypt" }, { value: 'b', label: 'ZeroSSL' }]} />,
  );
  await user.click(screen.getByRole('button', { name: 'Clear CA' }));
  expect(onChange).toHaveBeenCalledWith(undefined);
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

it('list input: an invalid entry shows an error that clears once you start fixing it', async () => {
  function H() {
    const [v, setV] = useState<string[]>([]);
    return <ListInput aria-label="Resolvers" value={v} onChange={setV} validate={(s) => (/^\d+\.\d+\.\d+\.\d+$/.test(s) ? null : 'Must be an IPv4 address')} />;
  }
  const { user } = renderUI(<H />);
  const input = screen.getByLabelText('Resolvers');
  await user.type(input, 'not-an-ip{Enter}');
  expect(screen.getByRole('alert')).toHaveTextContent('Must be an IPv4 address');
  expect(input).toHaveAttribute('aria-describedby', expect.stringContaining('-error'));
  await user.type(input, 'x');
  expect(screen.queryByRole('alert')).toBeNull();
});

it('field: links its error to a child input via aria-describedby and marks it invalid', () => {
  renderUI(
    <Field id="name" label="Name" error="Required">
      <Input id="name" />
    </Field>,
  );
  const input = screen.getByLabelText('Name');
  expect(input).toHaveAttribute('aria-describedby', 'name-error');
  expect(input).toHaveAttribute('aria-invalid', 'true');
  expect(screen.getByRole('alert')).toHaveTextContent('Required');
});

it('copy field writes to the clipboard', async () => {
  const { user } = renderUI(<CopyField value="ab:cd" label="fingerprint" />);
  await user.click(screen.getByRole('button', { name: 'Copy fingerprint' }));
  expect(await navigator.clipboard.readText()).toBe('ab:cd');
  expect(await screen.findByText('Copied')).toBeInTheDocument();
});

it('copy field shows a failure message when the clipboard write rejects', async () => {
  const original = navigator.clipboard;
  try {
    // renderUI's userEvent.setup() installs its own navigator.clipboard stub,
    // so the override has to happen after render (and after setup), not before.
    const { user } = renderUI(<CopyField value="ab:cd" label="fingerprint" />);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) },
    });
    await user.click(screen.getByRole('button', { name: 'Copy fingerprint' }));
    expect(await screen.findByText('Copy failed')).toBeInTheDocument();
  } finally {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: original });
  }
});

it('copy field shows a failure message when the Clipboard API is unavailable', async () => {
  const original = navigator.clipboard;
  try {
    const { user } = renderUI(<CopyField value="ab:cd" label="fingerprint" />);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    await user.click(screen.getByRole('button', { name: 'Copy fingerprint' }));
    expect(await screen.findByText('Copy failed')).toBeInTheDocument();
  } finally {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: original });
  }
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
