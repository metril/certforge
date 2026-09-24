import { expect, it } from 'vitest';
import { normalizeZone } from './zone';

it('passes through a plain zone, lowercased', () => {
  expect(normalizeZone('Example.COM')).toBe('example.com');
});

it('strips a pasted URL’s scheme and trailing path', () => {
  expect(normalizeZone('https://example.com/')).toBe('example.com');
  expect(normalizeZone('http://example.com/path?query#hash')).toBe('example.com');
});

it('trims surrounding whitespace', () => {
  expect(normalizeZone('  example.com  ')).toBe('example.com');
});

it('rejects internal whitespace', () => {
  expect(normalizeZone('exa mple.com')).toBeNull();
});

it('rejects an empty label from a leading, trailing, or doubled dot', () => {
  expect(normalizeZone('.example.com')).toBeNull();
  expect(normalizeZone('example.com.')).toBeNull();
  expect(normalizeZone('example..com')).toBeNull();
});

it('rejects empty input', () => {
  expect(normalizeZone('')).toBeNull();
  expect(normalizeZone('   ')).toBeNull();
});
