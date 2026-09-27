import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import type { DnsCredential } from '@/api/types';
import type { Coverage } from '@/lib/coverage';
import { renderUI } from '@/test/render';
import { CoveragePanel } from './CoveragePanel';

const creds: DnsCredential[] = [{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }];

it('shows the Global source label for a global catch-all', () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'inherited', source: 'global', rule: { match: '*', method: 'dns-01', dnsCredentialId: 'd-1', via: 'server' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('Catch-all: inherited from Global');
});

// Fix round 1 (review, item 4): an inherited rule missing a credential must
// say so is inherited, or the user goes looking for a rule of their own
// that doesn't exist.
it('labels an inherited rule missing a credential, not a bare "No credential"', () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'missing-credential', source: 'org', rule: { match: '*', method: 'dns-01', via: 'server' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('Inherited rule (Org): no credential');
});

it("labels the certificate's own rule missing a credential as a plain \"No credential\"", () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'missing-credential', ruleIndex: 0, rule: { match: 'example.com', method: 'dns-01', via: 'server' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('No credential');
  expect(row).not.toHaveTextContent('Inherited rule');
});

// Fix round 1 (review, Important): a wildcard sharing its apex's rule is
// marked so, since it isn't the wildcard's own direct match.
it('marks a wildcard row proven by its apex as "via apex"', () => {
  const items: Coverage[] = [
    { name: '*.example.com', state: 'rule', ruleIndex: 0, rule: { match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1', via: 'server' }, viaApex: true },
  ];
  renderUI(<CoveragePanel items={items} credentials={creds} />);
  const row = screen.getByText('*.example.com').closest('li')!;
  expect(row).toHaveTextContent('via apex');
});
