import { expect, it } from 'vitest';
import { explainAcmeError } from './acmeErrors';

it('maps known ACME error types to one line plus a fix', () => {
  expect(explainAcmeError('urn:ietf:params:acme:error:rateLimited')).toMatchObject({ text: 'The CA rate limit was reached.' });
  expect(explainAcmeError('caa')?.fix).toBeTruthy();
});

it('falls back for unknown types and ignores empty input', () => {
  expect(explainAcmeError('urn:ietf:params:acme:error:somethingNew')?.text).toBe('The CA returned somethingNew.');
  expect(explainAcmeError(undefined)).toBeNull();
});

it('links caa to its own docs anchor, not the general troubleshooting one', () => {
  expect(explainAcmeError('urn:ietf:params:acme:error:caa')?.href).toBe('guide/certificates.md#caa');
});

it('links rateLimited to the rate-limits docs anchor', () => {
  expect(explainAcmeError('urn:ietf:params:acme:error:rateLimited')?.href).toBe('guide/certificates.md#rate-limits');
});
