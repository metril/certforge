import { expect, it } from 'vitest';
import { briefOf, iso, makeCert, NOW } from '@/test/fixtures';
import { attentionItems, upcomingRenewals } from './attention';

const v = (notAfter: string) => ({ ...makeCert().currentVersion!, notAfter });

it('orders by severity, then time to impact, one item per certificate', () => {
  const certs = [
    makeCert({ id: 'overdue', nextRenewAt: iso(-2) }),
    makeCert({ id: 'failed-late', status: 'failed', failureCount: 3, lastError: 'dns: NXDOMAIN\nmore', currentVersion: v(iso(40)) }),
    makeCert({ id: 'failed-soon', status: 'failed', failureCount: 1, lastError: 'caa', currentVersion: v(iso(5)) }),
    makeCert({ id: 'expired', status: 'expired', currentVersion: v(iso(-3)) }),
    makeCert({ id: 'manual', status: 'pending', currentVersion: undefined, verificationRules: [{ match: 'lab.local', method: 'manual-dns', via: 'server' }] }),
    makeCert({ id: 'fine' }),
  ];
  const items = attentionItems(certs.map(briefOf), NOW);
  expect(items.map((i) => i.cert.id)).toEqual(['expired', 'manual', 'failed-soon', 'failed-late', 'overdue']);
  expect(items[0]!.cause).toBe('Expired 3 d ago');
  expect(items[3]!.cause).toBe('dns: NXDOMAIN');
});

it('lists renewals due within 7 days', () => {
  const certs = [makeCert({ id: 'a', nextRenewAt: iso(2) }), makeCert({ id: 'b', nextRenewAt: iso(9) }), makeCert({ id: 'c', status: 'failed' })];
  expect(upcomingRenewals(certs.map(briefOf), NOW).map((c) => c.id)).toEqual(['a']);
});

// Review fix: two certificates with no current version both carry
// `impactAt: +Infinity`; subtracting them (`Infinity - Infinity`) is `NaN`,
// which makes `Array.prototype.sort`'s result unspecified. A finite
// comparison plus an id tiebreak keeps this deterministic instead of
// flipping between runs/engines.
it('orders two versionless certificates of the same kind deterministically by id', () => {
  const certs = [
    makeCert({ id: 'z-cert', status: 'pending', currentVersion: undefined, verificationRules: [{ match: 'z.example.com', method: 'manual-dns', via: 'server' }] }),
    makeCert({ id: 'a-cert', status: 'pending', currentVersion: undefined, verificationRules: [{ match: 'a.example.com', method: 'manual-dns', via: 'server' }] }),
  ];
  const items = attentionItems(certs.map(briefOf), NOW);
  expect(items.map((i) => i.cert.id)).toEqual(['a-cert', 'z-cert']);
});
