import { useState } from 'react';
import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import type { VerificationMethod, VerificationRule } from '@/api/types';
import { renderUI } from '@/test/render';
import { VerificationRulesEditor } from './VerificationRulesEditor';

function Harness({ initial }: { initial: VerificationRule[] }) {
  const [rules, setRules] = useState(initial);
  const [method, setMethod] = useState<VerificationMethod>(initial[0]?.method ?? 'dns-01');
  return <VerificationRulesEditor rules={rules} onChange={setRules} method={method} onMethodChange={setMethod} credentials={[]} />;
}

// Fix round 1 (review, item 5): manual-dns needs no DNS credential, so
// neither the row's combobox nor the column-header tooltip should appear.
it('manual-dns hides the credential column and its header', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'manual-dns' }]} />);
  expect(screen.queryByRole('combobox', { name: 'Rule 1 credential' })).toBeNull();
  expect(screen.queryByText('Credential')).toBeNull();
  expect(screen.getByText('Match')).toBeInTheDocument();
});

it('dns-01 shows the credential column and its header', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'dns-01' }]} />);
  expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toBeInTheDocument();
  expect(screen.getByText('Credential')).toBeInTheDocument();
});

// Fix round 1 (review, item 2): a malformed match pattern (challenge/
// match.go's ParseMatch/validZone grammar) shows a one-line inline error.
it('shows a one-line inline error for a match pattern the server would reject', async () => {
  const { user } = renderUI(<Harness initial={[{ match: 'example.com', method: 'dns-01' }]} />);
  const input = screen.getByLabelText('Rule 1 match');
  await user.clear(input);
  await user.type(input, 'example.com/oops');
  expect(await screen.findByRole('alert')).toHaveTextContent(/letters, digits, hyphens/i);
});

it('shows no error for an empty freshly-added row', () => {
  renderUI(<Harness initial={[{ match: '', method: 'dns-01' }]} />);
  expect(screen.queryByRole('alert')).toBeNull();
});
