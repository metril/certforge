import { expect, it } from 'vitest';
import { safeRedirect } from './redirect';

it.each([
  [undefined, '/'],
  ['', '/'],
  ['https://evil.example/x', '/'],
  ['//evil.example', '/'],
  ['/\\evil.example', '/'],
  ['/login?redirect=/x', '/'],
  ['/setup', '/'],
  ['/o/acme/certificates?status=failed', '/o/acme/certificates?status=failed'],
  // Controller ruling: exact adversarial inputs to cover.
  ['https://evil.com', '/'],
  ['//evil.com', '/'],
  ['/\\evil.com', '/'],
  ['/o/acme/certificates?status=failed#top', '/o/acme/certificates?status=failed#top'],
  // Fix round 1 (review): safeRedirect must match the server's safeNext
  // (internal/api/oidc.go ~23-42) exactly.
  ['//evil', '/'],
  ['/\\evil', '/'],
  ['/\t/evil', '/'],
  ['/%2F%2Fevil', '/'],
  ['/%5Cevil', '/'],
  ['javascript:alert(1)', '/'],
  ['https://evil.example', '/'],
  ['/' + 'a'.repeat(2048), '/'],
])('safeRedirect(%s) → %s', (input, expected) => {
  expect(safeRedirect(input)).toBe(expected);
});
