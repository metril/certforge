import { expect, it } from 'vitest';
import { makeCert } from '@/test/fixtures';
import { makeSuggester, rememberCredentials } from './lastCredential';

const creds = [
  { id: 'd-1', name: 'CF', providerCode: 'cloudflare', config: {} },
  { id: 'd-2', name: 'R53', providerCode: 'route53', config: {} },
];

it('prefers the credential last used for the zone, then existing certificates', () => {
  const certs = [makeCert({ verificationRules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }] })];
  expect(makeSuggester(certs, creds)('example.com')).toBe('d-1');
  rememberCredentials([{ match: '*.example.com', method: 'dns-01', dnsCredentialId: 'd-2' }]);
  expect(makeSuggester(certs, creds)('example.com')).toBe('d-2');
  expect(makeSuggester(certs, creds)('other.net')).toBeUndefined();
});

it('ignores remembered credentials that no longer exist', () => {
  rememberCredentials([{ match: 'gone.test', method: 'dns-01', dnsCredentialId: 'd-9' }]);
  expect(makeSuggester([], creds)('gone.test')).toBeUndefined();
});
