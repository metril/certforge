import { describe, expect, it } from 'vitest';
import { fmtInterval, INTERVALS, shortFp } from './monitors';

describe('fmtInterval', () => {
  it('uses preset labels', () => {
    expect(fmtInterval(300)).toBe('5 m');
    expect(fmtInterval(900)).toBe('15 m');
    expect(fmtInterval(3600)).toBe('1 h');
    expect(fmtInterval(21_600)).toBe('6 h');
    expect(fmtInterval(86_400)).toBe('24 h');
  });

  it('formats a non-preset custom interval in minutes', () => {
    expect(fmtInterval(5400)).toBe('90 m');
  });

  it('every preset has a value and a label', () => {
    expect(INTERVALS).toHaveLength(5);
    for (const i of INTERVALS) {
      expect(i.value).toBeGreaterThan(0);
      expect(i.label).toBeTruthy();
    }
  });
});

describe('shortFp', () => {
  it('truncates to 16 hex chars plus an ellipsis', () => {
    const fp = 'ab'.repeat(32);
    expect(shortFp(fp)).toBe(`${fp.slice(0, 16)}…`);
  });

  it('leaves a short value alone', () => {
    expect(shortFp('abcd')).toBe('abcd');
  });
});
