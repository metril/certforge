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
