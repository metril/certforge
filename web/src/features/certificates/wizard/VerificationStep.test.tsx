import { useReducer } from 'react';
import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { DnsCredential } from '@/api/types';
import { server } from '@/test/server';
import { makeCert, providers, url } from '@/test/fixtures';
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
  return (
    <>
      <VerificationStep orgId="org-1" state={state} dispatch={dispatch} inherited={inherited} />
      <output data-testid="ready">{String(verificationReady(state.names, state.rules, inherited))}</output>
    </>
  );
}

// A single name so a second, narrower rule can be added and moved above the
// pre-filled zone rule to exercise first-match-wins under reordering.
function HOne() {
  const [state, dispatch] = useReducer(wizardReducer, wizardReducer(initialWizard, { type: 'addNames', names: ['a.example.com'] }));
  return (
    <>
      <VerificationStep orgId="org-1" state={state} dispatch={dispatch} inherited={null} />
      <output data-testid="ready">{String(verificationReady(state.names, state.rules, null))}</output>
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
  renderUI(<H inherited={{ rules: [{ match: '*', method: 'dns-01', dnsCredentialId: 'd-1' }], source: 'org' }} />);
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
  expect(row).toHaveTextContent('Rule 1: example.com → Cloudflare prod');
  expect(screen.getByTestId('ready')).toHaveTextContent('true');

  await user.click(screen.getByLabelText('Move rule 2 up'));
  await waitFor(() => expect(screen.getByLabelText('Rule 1 match')).toHaveValue('a.example.com'));
  row = within(screen.getByRole('region', { name: 'Coverage' })).getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('No credential');
  expect(screen.getByTestId('ready')).toHaveTextContent('false');
});
