import { useReducer } from 'react';
import { useQuery } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { allClientsQuery } from '@/api/queries/clients';
import type { DnsCredential } from '@/api/types';
import { server } from '@/test/server';
import { makeCert, makeClient, providers, url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { verificationReady, type Inherited } from '@/lib/coverage';
import { initialWizard, wizardReducer } from './state';
import { VerificationStep } from './VerificationStep';

let creds: DnsCredential[];
beforeEach(() => {
  creds = [{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }];
  server.use(
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json(creds)),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: providers, deployTargets: [], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/orgs/org-1/clients'), () =>
      HttpResponse.json({
        items: [
          makeClient({ id: 'cl-http', name: 'web-1', status: 'active', capabilities: ['http-01'] }),
          makeClient({ id: 'cl-alpn', name: 'web-2', status: 'active', capabilities: ['tls-alpn-01'] }),
          makeClient({ id: 'cl-none', name: 'web-3', status: 'active', capabilities: [] }),
        ],
        nextCursor: null,
      }),
    ),
    http.post(url('/orgs/org-1/dns-credentials'), async ({ request }) => {
      const body = (await request.json()) as Omit<DnsCredential, 'id'>;
      const created = { ...body, id: 'd-9' };
      creds = [...creds, created];
      return HttpResponse.json(created, { status: 201 });
    }),
  );
});

function H({ inherited }: { inherited: Inherited }) {
  const [state, dispatch] = useReducer(wizardReducer, wizardReducer(initialWizard, { type: 'addNames', names: ['www.example.com', '*.example.com', 'api.other.net'] }));
  const clients = useQuery(allClientsQuery('org-1')).data?.items ?? [];
  return (
    <>
      <VerificationStep orgId="org-1" state={state} dispatch={dispatch} inherited={inherited} />
      <output data-testid="ready">{String(verificationReady(state.names, state.rules, inherited, clients))}</output>
      <output data-testid="rules">{JSON.stringify(state.rules)}</output>
    </>
  );
}

// A single name so a second, narrower rule can be added and moved above the
// pre-filled zone rule to exercise first-match-wins under reordering.
function HOne() {
  const [state, dispatch] = useReducer(wizardReducer, wizardReducer(initialWizard, { type: 'addNames', names: ['a.example.com'] }));
  const clients = useQuery(allClientsQuery('org-1')).data?.items ?? [];
  return (
    <>
      <VerificationStep orgId="org-1" state={state} dispatch={dispatch} inherited={null} />
      <output data-testid="ready">{String(verificationReady(state.names, state.rules, null, clients))}</output>
    </>
  );
}

it('prefills per zone and marks a zone with no credential as blocked', async () => {
  renderUI(<H inherited={null} />);
  await waitFor(() => expect(screen.getByLabelText('Rule 1 match')).toHaveValue('example.com'));
  expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod');
  expect(screen.getByLabelText('Rule 2 match')).toHaveValue('other.net');
  expect(screen.getByRole('combobox', { name: 'Rule 2 credential' })).toHaveTextContent('Choose credential');
  const row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('api.other.net').closest('li')!;
  expect(row).toHaveTextContent('No credential');
  expect(screen.getByTestId('ready')).toHaveTextContent('false');
});

it('lets an inherited catch-all cover the zone instead of adding an empty rule', async () => {
  renderUI(<H inherited={{ rules: [{ match: '*', method: 'dns-01', dnsCredentialId: 'd-1', via: 'server' }], source: 'org' }} />);
  await waitFor(() => expect(screen.getByLabelText('Rule 1 match')).toHaveValue('example.com'));
  expect(screen.queryByLabelText('Rule 2 match')).toBeNull();
  const row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('api.other.net').closest('li')!;
  expect(row).toHaveTextContent('Catch-all: inherited from Org');
  expect(screen.getByTestId('ready')).toHaveTextContent('true');
});

it('creates a credential from a rule without leaving the step', async () => {
  const { user } = renderUI(<H inherited={null} />);
  await waitFor(() => expect(screen.getByLabelText('Rule 2 match')).toHaveValue('other.net'));
  await user.click(screen.getByRole('combobox', { name: 'Rule 2 credential' }));
  await user.click(screen.getByRole('button', { name: 'Add credential' }));
  await user.type(await screen.findByPlaceholderText('cloudflare'), 'cloudfl');
  await user.click(screen.getAllByRole('option').find((o) => o.getAttribute('data-value') === 'all:cloudflare')!);
  const sheet = await screen.findByRole('dialog', { name: 'Add Cloudflare credential' });
  await user.clear(within(sheet).getByLabelText('Name'));
  await user.type(within(sheet).getByLabelText('Name'), 'Cloudflare other');
  // Adaptation: the brief's test targeted the secret widget via its sr-only
  // "New value" hint (linked by aria-describedby), which getByLabelText
  // does not resolve to a form control. SecretInput (Task 9, already
  // committed) also gives the input its own aria-label of the field name
  // itself — the same selector credentials.test.tsx already uses.
  await user.type(within(sheet).getByLabelText('CF_DNS_API_TOKEN'), 'tok');
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 2 credential' })).toHaveTextContent('Cloudflare other'));
  expect(screen.getByTestId('ready')).toHaveTextContent('true');
});

it('moving a rule up with the keyboard changes which one covers a name (first match wins)', async () => {
  const { user } = renderUI(<HOne />);
  await waitFor(() => expect(screen.getByLabelText('Rule 1 match')).toHaveValue('example.com'));

  await user.click(screen.getByRole('button', { name: 'Add rule' }));
  await user.type(screen.getByLabelText('Rule 2 match'), 'a.example.com');
  let row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('Rule 1: example.com → DNS · Cloudflare prod');
  expect(screen.getByTestId('ready')).toHaveTextContent('true');

  await user.click(screen.getByLabelText('Move rule 2 up'));
  await waitFor(() => expect(screen.getByLabelText('Rule 1 match')).toHaveValue('a.example.com'));
  row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('No credential');
  expect(screen.getByTestId('ready')).toHaveTextContent('false');
});

it('per-row method: switching row 2 to HTTP, Agent and picking a client dispatches a mixed-method rule set', async () => {
  const { user } = renderUI(<H inherited={null} />);
  await waitFor(() => expect(screen.getByLabelText('Rule 2 match')).toHaveValue('other.net'));
  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 2 method' })).getByRole('radio', { name: 'HTTP' }));
  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 2 served by' })).getByRole('radio', { name: 'Agent' }));
  await user.click(screen.getByRole('combobox', { name: 'Rule 2 client' }));
  await user.click(await screen.findByRole('option', { name: 'web-1' }));
  await waitFor(() =>
    expect(JSON.parse(screen.getByTestId('rules').textContent ?? '[]')).toEqual([
      { match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' },
      { match: 'other.net', method: 'http-01', via: 'agent', clientId: 'cl-http' },
    ]),
  );
});

it('only capable clients: a client without tls-alpn-01 is not offered on a TLS-ALPN row', async () => {
  const { user } = renderUI(<H inherited={null} />);
  await waitFor(() => expect(screen.getByLabelText('Rule 2 match')).toHaveValue('other.net'));
  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 2 method' })).getByRole('radio', { name: 'TLS-ALPN' }));
  await user.click(screen.getByRole('combobox', { name: 'Rule 2 client' }));
  expect(await screen.findByRole('option', { name: 'web-2' })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: 'web-1' })).toBeNull();
});

// Controller ruling (review fix round 2): coverage()/verificationReady() now
// check an agent-mode rule's client against the method's capability (or a
// webroot), not just its clientId presence — end to end, through the
// Coverage panel and the wizard's own Next/Issue gate.
it('an agent client with no capability is incomplete; a webroot covers it; clearing the webroot makes it incomplete again', async () => {
  const { user } = renderUI(<H inherited={null} />);
  await waitFor(() => expect(screen.getByLabelText('Rule 1 match')).toHaveValue('example.com'));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));

  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 2 method' })).getByRole('radio', { name: 'HTTP' }));
  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 2 served by' })).getByRole('radio', { name: 'Agent' }));
  const row2 = screen.getByRole('radiogroup', { name: 'Rule 2 method' }).closest('li')!;
  await user.click(within(row2).getByRole('button', { name: 'Advanced' }));
  const webroot = screen.getByLabelText('Webroot');
  await user.type(webroot, '/srv/acme');

  // A webroot lists every active client, capable or not — pick the one with no capability.
  await user.click(screen.getByRole('combobox', { name: 'Rule 2 client' }));
  await user.click(await screen.findByRole('option', { name: 'web-3' }));
  let row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('api.other.net').closest('li')!;
  await waitFor(() => expect(row).toHaveTextContent('Rule 2: other.net → HTTP · web-3'));
  expect(screen.getByTestId('ready')).toHaveTextContent('true');

  // Clearing the webroot leaves the same, still-incapable client picked —
  // the row must go back to incomplete, and block the wizard step.
  await user.clear(webroot);
  row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('api.other.net').closest('li')!;
  await waitFor(() => expect(row).toHaveTextContent('No client'));
  expect(screen.getByTestId('ready')).toHaveTextContent('false');
});

it('coverage shows the method: DNS · credential, then HTTP · client once switched', async () => {
  const { user } = renderUI(<H inherited={null} />);
  await waitFor(() => expect(screen.getByLabelText('Rule 1 match')).toHaveValue('example.com'));
  let row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('www.example.com').closest('li')!;
  expect(row).toHaveTextContent('Rule 1: example.com → DNS · Cloudflare prod');

  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 2 method' })).getByRole('radio', { name: 'HTTP' }));
  await user.click(within(screen.getByRole('radiogroup', { name: 'Rule 2 served by' })).getByRole('radio', { name: 'Agent' }));
  await user.click(screen.getByRole('combobox', { name: 'Rule 2 client' }));
  await user.click(await screen.findByRole('option', { name: 'web-1' }));
  row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('api.other.net').closest('li')!;
  expect(row).toHaveTextContent('Rule 2: other.net → HTTP · web-1');
});
