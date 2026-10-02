import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import type { Client, DnsCredential } from '@/api/types';
import type { Coverage } from '@/lib/coverage';
import { makeClient } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { CoveragePanel } from './CoveragePanel';

const creds: DnsCredential[] = [{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }];
const clients: Client[] = [makeClient({ id: 'c-1', name: 'web-1' })];

it('shows the method and target: DNS with its credential', () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'rule', ruleIndex: 0, rule: { match: 'a.example.com', method: 'dns-01', dnsCredentialId: 'd-1' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('Rule 1: a.example.com → DNS · Cloudflare prod');
});

it('shows the method and target: HTTP served by server', () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'rule', ruleIndex: 1, rule: { match: 'a.example.com', method: 'http-01', via: 'server' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('Rule 2: a.example.com → HTTP · server');
});

it('shows the method and target: TLS-ALPN with its client', () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'rule', ruleIndex: 0, rule: { match: 'a.example.com', method: 'tls-alpn-01', clientId: 'c-1' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('Rule 1: a.example.com → TLS-ALPN · web-1');
});

it('shows the Global source label for a global catch-all', () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'inherited', source: 'global', rule: { match: '*', method: 'dns-01', dnsCredentialId: 'd-1' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('Catch-all: inherited from Global');
});

// Fix round 1 (review, item 4): an inherited rule missing a credential must
// say so is inherited, or the user goes looking for a rule of their own
// that doesn't exist.
it('labels an inherited rule missing a credential, not a bare "No credential"', () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'incomplete', source: 'org', rule: { match: '*', method: 'dns-01' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('Inherited rule (Organization): no credential');
});

it("labels the certificate's own rule missing a credential as a plain \"No credential\"", () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'incomplete', ruleIndex: 0, rule: { match: 'example.com', method: 'dns-01' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('No credential');
  expect(row).not.toHaveTextContent('Inherited rule');
});

it('labels an agent rule with no client as "No client"', () => {
  const items: Coverage[] = [{ name: 'a.example.com', state: 'incomplete', ruleIndex: 0, rule: { match: 'example.com', method: 'tls-alpn-01' } }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('a.example.com').closest('li')!;
  expect(row).toHaveTextContent('No client');
});

it('marks a wildcard resolving only to an http-01/tls-alpn-01 rule as needing a DNS method', () => {
  const items: Coverage[] = [{ name: '*.a.test', state: 'wildcard-non-dns' }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('*.a.test').closest('li')!;
  expect(row).toHaveTextContent('Wildcards need a DNS method');
});

it('says an IP name is unsupported', () => {
  const items: Coverage[] = [{ name: '10.0.0.1', state: 'ip' }];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('10.0.0.1').closest('li')!;
  expect(row).toHaveTextContent("IP names aren't supported");
});

// Fix round 1 (review, Important): a wildcard sharing its apex's rule is
// marked so, since it isn't the wildcard's own direct match.
it('marks a wildcard row proven by its apex as "via apex"', () => {
  const items: Coverage[] = [
    { name: '*.example.com', state: 'rule', ruleIndex: 0, rule: { match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }, viaApex: true },
  ];
  renderUI(<CoveragePanel items={items} credentials={creds} clients={clients} />);
  const row = screen.getByText('*.example.com').closest('li')!;
  expect(row).toHaveTextContent('via apex');
});
