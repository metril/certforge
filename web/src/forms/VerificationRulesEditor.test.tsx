import { useState } from 'react';
import { screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import type { VerificationRule } from '@/api/types';
import { help } from '@/lib/help';
import { makeClient } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { VerificationRulesEditor } from './VerificationRulesEditor';

const clients = [
  makeClient({ id: 'cl-http', name: 'web-1', status: 'active', capabilities: ['http-01'] }),
  makeClient({ id: 'cl-alpn', name: 'web-2', status: 'active', capabilities: ['tls-alpn-01'] }),
];

function Harness({ initial, agentModes }: { initial: VerificationRule[]; agentModes?: boolean }) {
  const [rules, setRules] = useState(initial);
  return <VerificationRulesEditor rules={rules} onChange={setRules} credentials={[]} clients={clients} agentModes={agentModes} />;
}

it('every row picks its own method, DNS / Manual / HTTP / TLS-ALPN', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'dns-01' }]} />);
  expect(screen.getByRole('radiogroup', { name: 'Rule 1 method' })).toBeInTheDocument();
  expect(screen.getByRole('radio', { name: 'DNS' })).toBeInTheDocument();
  expect(screen.getByRole('radio', { name: 'Manual' })).toBeInTheDocument();
  expect(screen.getByRole('radio', { name: 'HTTP' })).toBeInTheDocument();
  expect(screen.getByRole('radio', { name: 'TLS-ALPN' })).toBeInTheDocument();
});

it('manual-dns hides the credential combobox', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'manual-dns' }]} />);
  expect(screen.queryByRole('combobox', { name: 'Rule 1 credential' })).toBeNull();
});

it('dns-01 shows the credential combobox', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'dns-01' }]} />);
  expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toBeInTheDocument();
});

it('http-01 shows Served by, defaulting to server with no client picker', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'http-01', via: 'server' }]} />);
  expect(screen.getByRole('radiogroup', { name: 'Rule 1 served by' })).toBeInTheDocument();
  expect(screen.getByRole('radio', { name: 'Server' })).toHaveAttribute('aria-checked', 'true');
  expect(screen.queryByRole('combobox', { name: 'Rule 1 client' })).toBeNull();
});

it('http-01 via agent shows a client combobox filtered by capability', async () => {
  const { user } = renderUI(<Harness initial={[{ match: 'example.com', method: 'http-01', via: 'agent' }]} />);
  const combo = screen.getByRole('combobox', { name: 'Rule 1 client' });
  await user.click(combo);
  expect(screen.getByRole('option', { name: 'web-1' })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: 'web-2' })).toBeNull();
});

it('tls-alpn-01 shows a client combobox filtered by its own capability, no Served by', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'tls-alpn-01' }]} />);
  expect(screen.queryByRole('radiogroup', { name: 'Rule 1 served by' })).toBeNull();
  expect(screen.getByRole('combobox', { name: 'Rule 1 client' })).toBeInTheDocument();
});

it('switching a row to HTTP clears its DNS credential and defaults via to server', async () => {
  const { user } = renderUI(<Harness initial={[{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }]} />);
  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 1 method' })).getByRole('radio', { name: 'HTTP' }));
  expect(screen.getByRole('radio', { name: 'Server' })).toHaveAttribute('aria-checked', 'true');
  expect(screen.queryByRole('combobox', { name: 'Rule 1 credential' })).toBeNull();
});

it('"Add rule" copies the previous row\'s method', async () => {
  const { user } = renderUI(<Harness initial={[{ match: 'example.com', method: 'tls-alpn-01' }]} />);
  await user.click(screen.getByRole('button', { name: 'Add rule' }));
  expect(screen.getByRole('combobox', { name: 'Rule 2 client' })).toBeInTheDocument();
});

it('"Add rule" with no rows yet defaults to dns-01', async () => {
  const { user } = renderUI(<Harness initial={[]} />);
  await user.click(screen.getByRole('button', { name: 'Add rule' }));
  expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toBeInTheDocument();
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

it('the column header row reads Match, Method, Details', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'dns-01' }]} />);
  expect(screen.getByText('Match')).toBeInTheDocument();
  expect(screen.getByText('Method')).toBeInTheDocument();
  expect(screen.getByText('Details')).toBeInTheDocument();
});

it('shows a HelpTip next to the DNS credential combobox', () => {
  renderUI(<Harness initial={[{ match: 'example.com', method: 'dns-01' }]} />);
  const combo = screen.getByRole('combobox', { name: 'Rule 1 credential' });
  // combo.closest('div') is Combobox's own internal wrapper; the row wraps
  // that plus the HelpTip in one more div around it.
  expect(within(combo.closest('div')!.parentElement!).getByLabelText('Help')).toBeInTheDocument();
});

// Review fix round 1 (Important): the Global tab's issuance defaults have
// no org, so a client picked for an agent-mode rule there can never work
// (022 on Save). agentModes={false} disables the two segments that need a
// client, each with a tooltip explaining why.
it('agentModes=false disables TLS-ALPN and Served by Agent, each with a hint', async () => {
  const { user } = renderUI(<Harness initial={[{ match: 'example.com', method: 'dns-01' }]} agentModes={false} />);
  const tlsAlpn = screen.getByRole('radio', { name: 'TLS-ALPN' });
  expect(tlsAlpn).toBeDisabled();
  await user.hover(tlsAlpn);
  expect(await screen.findByRole('tooltip')).toHaveTextContent(help['rules.globalAgentDisabled'].text);

  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 1 method' })).getByRole('radio', { name: 'HTTP' }));
  const agent = screen.getByRole('radio', { name: 'Agent' });
  expect(agent).toBeDisabled();
  await user.hover(agent);
  expect(await screen.findByRole('tooltip')).toHaveTextContent(help['rules.globalAgentDisabled'].text);
});

it('agentModes=false still renders an existing agent-mode row normally (empty-state text, not hidden)', async () => {
  const rules: VerificationRule[] = [{ match: 'example.com', method: 'tls-alpn-01' }];
  const { user } = renderUI(<VerificationRulesEditor rules={rules} onChange={() => {}} credentials={[]} clients={[]} agentModes={false} />);
  await user.click(screen.getByRole('combobox', { name: 'Rule 1 client' }));
  expect(await screen.findByText('No client serves tls-alpn-01')).toBeInTheDocument();
});

// Fix wave (Important): webrootError tolerated a trailing slash so Save
// never blocked on it, but the server's cleanWebroot rejects one — the
// stored value must actually drop it once typing settles (blur), not just
// validate as if it had.
it('strips a typed trailing slash from an agent webroot once it loses focus', async () => {
  const { user } = renderUI(<Harness initial={[{ match: 'example.com', method: 'http-01', via: 'agent', clientId: 'cl-http' }]} />);
  await user.click(screen.getByRole('button', { name: 'Advanced' }));
  const input = screen.getByLabelText('Webroot');
  await user.type(input, '/srv/acme/');
  expect(input).toHaveValue('/srv/acme/');
  await user.tab();
  expect(input).toHaveValue('/srv/acme');
});
