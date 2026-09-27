import { expect, it } from 'vitest';
import { generatePassword } from './password';

// A-Z minus O and I, a-z minus l, 0-9 minus 0 and 1.
const ALLOWED = /^[A-HJ-NP-Za-km-z2-9]+$/;

it('generates a 24-character password from the allowed alphabet', () => {
  const pw = generatePassword();
  expect(pw).toHaveLength(24);
  expect(pw).toMatch(ALLOWED);
});

it('produces 100 distinct passwords', () => {
  const seen = new Set(Array.from({ length: 100 }, () => generatePassword()));
  expect(seen.size).toBe(100);
});
