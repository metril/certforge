import { expect, it } from 'vitest';
import { DAY, HOUR, daysUntil, fmtDuration, relDays, relTime } from './time';

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

it('formats recent times', () => {
  const now = Date.parse('2026-09-24T12:00:00Z');
  expect(relTime('2026-09-24T11:59:40Z', now)).toBe('just now');
  expect(relTime('2026-09-24T11:55:00Z', now)).toBe('5 min ago');
  expect(relTime('2026-09-24T09:00:00Z', now)).toBe('3 h ago');
  expect(relTime('2026-09-21T12:00:00Z', now)).toBe('3 d ago');
});

it('handles the just-now / minute and hour / day boundaries', () => {
  const now = Date.parse('2026-09-24T12:00:00Z');
  expect(relTime(new Date(now - 59_000).toISOString(), now)).toBe('just now');
  expect(relTime(new Date(now - 60_000).toISOString(), now)).toBe('1 min ago');
  expect(relTime(new Date(now - 24 * HOUR).toISOString(), now)).toBe('1 d ago');
});

// A future timestamp within the just-now threshold (clock skew, or `now` not
// yet advanced past a just-received event) still reads as "just now".
it('clamps a future timestamp to "just now"', () => {
  const now = Date.parse('2026-09-24T12:00:00Z');
  expect(relTime(new Date(now + 5_000).toISOString(), now)).toBe('just now');
});

// Rate-ledger reset times are in the future by minutes, hours or days — used
// as `resets ${relTime(resetsAt)}`, e.g. "resets in 2 h".
it('formats a future timestamp as "in ..."', () => {
  const now = Date.parse('2026-09-24T12:00:00Z');
  expect(relTime(new Date(now + 5 * 60_000).toISOString(), now)).toBe('in 5 min');
  expect(relTime(new Date(now + 2 * HOUR).toISOString(), now)).toBe('in 2 h');
  expect(relTime(new Date(now + 3 * DAY).toISOString(), now)).toBe('in 3 d');
});
