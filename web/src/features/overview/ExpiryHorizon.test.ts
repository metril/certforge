import { expect, it } from 'vitest';
import { briefOf, iso, makeCert, NOW } from '@/test/fixtures';
import { horizonTicks, rangeToDays } from './ExpiryHorizon';

it('places ticks on a 90-day axis and counts later expiries', () => {
  const certs = [
    makeCert({ id: 'a', currentVersion: { ...makeCert().currentVersion!, notAfter: iso(45) }, nextRenewAt: iso(15) }),
    makeCert({ id: 'b', currentVersion: { ...makeCert().currentVersion!, notAfter: iso(200) } }),
    makeCert({ id: 'c', currentVersion: undefined, status: 'pending' }),
  ];
  const { ticks, beyond } = horizonTicks(certs.map(briefOf), NOW);
  expect(ticks).toHaveLength(1);
  expect(ticks[0]!.x).toBeCloseTo(500, 0);
  expect(ticks[0]!.windowFrom).toBeCloseTo(166.7, 0);
  expect(beyond).toBe(1);
});

it('converts a brushed span to whole days in either direction', () => {
  expect(rangeToDays(1000, 333.4)).toEqual([30, 90]);
});

it('skips revoked certificates', () => {
  const certs = [makeCert({ id: 'r', status: 'revoked', currentVersion: { ...makeCert().currentVersion!, notAfter: iso(10) } })];
  expect(horizonTicks(certs.map(briefOf), NOW)).toEqual({ ticks: [], beyond: 0 });
});
