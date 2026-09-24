import { expect, it } from 'vitest';
import { DAY, daysUntil, fmtDuration, relDays } from './time';

const now = Date.parse('2026-09-24T12:00:00Z');

it.each([
  [now + 3 * DAY, 3],
  [now + 5 * 3_600_000, 1],
  [now - 5 * 3_600_000, -1],
  [now - 2 * DAY, -2],
])('daysUntil(%s) = %s', (t, d) => expect(daysUntil(t, now)).toBe(d));

it('formats relative days', () => {
  expect(relDays(new Date(now + 12 * DAY).toISOString(), now)).toBe('in 12 d');
  expect(relDays(new Date(now - 3 * DAY).toISOString(), now)).toBe('3 d ago');
  expect(relDays(new Date(now).toISOString(), now)).toBe('today');
});

it.each([
  [850, '850 ms'],
  [4_200, '4.2 s'],
  [125_000, '2 min 5 s'],
])('fmtDuration(%s) = %s', (ms, s) => expect(fmtDuration(ms)).toBe(s));
