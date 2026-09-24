import { afterEach, expect, it, vi } from 'vitest';
import { pushRecent, readRecent } from './recent';

afterEach(() => {
  vi.restoreAllMocks();
});

it('persists recent provider codes, most recent first, deduped', () => {
  pushRecent('cloudflare');
  pushRecent('route53');
  pushRecent('cloudflare');
  expect(readRecent()).toEqual(['cloudflare', 'route53']);
});

it('never throws when storage is blocked; reads fall back to empty', () => {
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('blocked');
  });
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
    throw new Error('blocked');
  });
  expect(() => pushRecent('cloudflare')).not.toThrow();
  expect(readRecent()).toEqual([]);
});
