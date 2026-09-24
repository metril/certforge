import { expect, it } from 'vitest';
import { coverage, matchRule, prefillRules, verificationReady } from './coverage';

it.each([
  ['www.example.com', 'example.com', true],
  ['example.com', 'example.com', true],
  ['*.example.com', 'example.com', true],
  ['notexample.com', 'example.com', false],
  ['a.example.com', '*.example.com', true],
  ['a.b.example.com', '*.example.com', false],
  ['*.example.com', '*.example.com', true],
  ['*.a.example.com', '*.example.com', false],
  ['anything.test', '*', true],
  ['EXAMPLE.com.', 'example.com', true],
])('matchRule(%s, %s) = %s', (name, pattern, expected) => expect(matchRule(name, pattern)).toBe(expected));

const names = ['www.example.com', '*.example.com', 'api.other.net', '10.0.0.1'];

it('reports first-match rules, missing credentials, inherited catch-all, and IPs', () => {
  const c = coverage(names, [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }, { match: 'other.net', method: 'dns-01' }], null);
  expect(c.map((x) => x.state)).toEqual(['rule', 'rule', 'missing-credential', 'ip']);
  const inh = { rules: [{ match: '*', method: 'dns-01' as const, dnsCredentialId: 'd-2' }], source: 'org' as const };
  expect(coverage(['api.other.net'], [], inh)[0]).toMatchObject({ state: 'inherited', source: 'org' });
  expect(verificationReady(['api.other.net'], [], inh)).toBe(true);
  expect(verificationReady(['api.other.net'], [], null)).toBe(false);
});

it('prefills one rule per zone, never guesses a credential, and leans on a catch-all', () => {
  const suggest = (z: string) => (z === 'example.com' ? 'd-1' : undefined);
  expect(prefillRules(names, 'dns-01', suggest, null)).toEqual([
    { match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' },
    { match: 'other.net', method: 'dns-01' },
  ]);
  const inh = { rules: [{ match: '*', method: 'dns-01' as const, dnsCredentialId: 'd-2' }], source: 'org' as const };
  expect(prefillRules(names, 'dns-01', suggest, inh)).toEqual([{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }]);
  expect(prefillRules(names, 'manual-dns', suggest, null)).toEqual([
    { match: 'example.com', method: 'manual-dns' },
    { match: 'other.net', method: 'manual-dns' },
  ]);
});
