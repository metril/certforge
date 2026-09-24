import { expect, it } from 'vitest';
import { makeCert } from '@/test/fixtures';
import { makeSuggester, rememberFromRules } from './lastCredential';

const creds = [
  { id: 'd-1', name: 'CF', providerCode: 'cloudflare', config: {} },
  { id: 'd-2', name: 'R53', providerCode: 'route53', config: {} },
];

it('prefers the credential last used for the zone, then existing certificates', () => {
  const certs = [makeCert({ verificationRules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }] })];
  expect(makeSuggester(certs, creds)('example.com')).toBe('d-1');
  rememberFromRules([{ match: '*.example.com', method: 'dns-01', dnsCredentialId: 'd-2' }]);
  expect(makeSuggester(certs, creds)('example.com')).toBe('d-2');
  expect(makeSuggester(certs, creds)('other.net')).toBeUndefined();
});

it('ignores remembered credentials that no longer exist', () => {
  rememberFromRules([{ match: 'gone.test', method: 'dns-01', dnsCredentialId: 'd-9' }]);
  expect(makeSuggester([], creds)('gone.test')).toBeUndefined();
});

// Fix round 1 (review, item 3): the remembered key is a normalised
// (lowercase, IDNA A-label) zone, so a rule written in a different case or
// script still resolves for a lookup zone that's already normalised
// (classifyName only ever hands makeSuggester an already-lowercase,
// already-ASCII zone).
it('remembers and looks up by normalised (lowercase, IDNA) zone', () => {
  rememberFromRules([{ match: '*.EXAMPLE.NET.', method: 'dns-01', dnsCredentialId: 'd-1' }]);
  expect(makeSuggester([], creds)('example.net')).toBe('d-1');
});
