import { expect, it } from 'vitest';
import { iso, makeCert, NOW } from '@/test/fixtures';
import { attentionItems, statusCounts, upcomingRenewals } from './attention';

const v = (notAfter: string) => ({ ...makeCert().currentVersion!, notAfter });

it('orders by severity, then time to impact, one item per certificate', () => {
  const certs = [
    makeCert({ id: 'overdue', nextRenewAt: iso(-2) }),
    makeCert({ id: 'failed-late', status: 'failed', failureCount: 3, lastError: 'dns: NXDOMAIN\nmore', currentVersion: v(iso(40)) }),
    makeCert({ id: 'failed-soon', status: 'failed', failureCount: 1, lastError: 'caa', currentVersion: v(iso(5)) }),
    makeCert({ id: 'expired', status: 'expired', currentVersion: v(iso(-3)) }),
    makeCert({ id: 'manual', status: 'pending', currentVersion: undefined, verificationRules: [{ match: 'lab.local', method: 'manual-dns' }] }),
    makeCert({ id: 'fine' }),
  ];
  const items = attentionItems(certs, NOW);
  expect(items.map((i) => i.cert.id)).toEqual(['expired', 'manual', 'failed-soon', 'failed-late', 'overdue']);
  expect(items[0]!.cause).toBe('Expired 3 d ago');
  expect(items[3]!.cause).toBe('dns: NXDOMAIN');
});

it('counts statuses and lists renewals due within 7 days', () => {
  const certs = [makeCert({ id: 'a', nextRenewAt: iso(2) }), makeCert({ id: 'b', nextRenewAt: iso(9) }), makeCert({ id: 'c', status: 'failed' })];
  expect(statusCounts(certs)).toEqual({ active: 2, pending: 0, failed: 1, expired: 0 });
  expect(upcomingRenewals(certs, NOW).map((c) => c.id)).toEqual(['a']);
});
