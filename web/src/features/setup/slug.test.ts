import { expect, it } from 'vitest';
import { SLUG_RE, toSlug } from './slug';

it.each([
  ['Acme Corp', 'acme-corp'],
  ['  Ünïcode Straße ', 'unicode-strae'],
  ['--Lab!!Net--', 'lab-net'],
  ['x'.repeat(60), 'x'.repeat(40)],
])('toSlug(%s) → %s', (name, slug) => {
  expect(toSlug(name)).toBe(slug);
  expect(SLUG_RE.test(slug)).toBe(true);
});
