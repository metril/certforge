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
])('safeRedirect(%s) → %s', (input, expected) => {
  expect(safeRedirect(input)).toBe(expected);
});
