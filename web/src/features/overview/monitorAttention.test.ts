import { expect, it } from 'vitest';
import { makeMonitor } from '@/test/fixtures';
import { monitorAttentionItems } from './monitorAttention';

it('mismatch and unreachable become items', () => {
  const items = monitorAttentionItems([
    makeMonitor({ id: 'a', state: 'mismatch', lastFingerprint: 'ab'.repeat(32), expectedCertificateName: 'www.example.com' }),
    makeMonitor({ id: 'b', state: 'mismatch', lastFingerprint: 'cd'.repeat(32), expectedCertificateName: null }),
    makeMonitor({ id: 'c', state: 'unreachable', lastError: 'dial tcp: connection refused\nmore detail' }),
  ]);
  expect(items).toEqual([
    { kind: 'monitor-mismatch', monitor: expect.objectContaining({ id: 'a' }), cause: `Serving ${'ab'.repeat(8)}…; expected www.example.com` },
    { kind: 'monitor-mismatch', monitor: expect.objectContaining({ id: 'b' }), cause: `Serving ${'cd'.repeat(8)}…; expected a CertForge certificate` },
    { kind: 'monitor-unreachable', monitor: expect.objectContaining({ id: 'c' }), cause: 'Unreachable: dial tcp: connection refused' },
  ]);
});

it('disabled and ok monitors skipped', () => {
  const items = monitorAttentionItems([
    makeMonitor({ id: 'a', state: 'mismatch', enabled: false }),
    makeMonitor({ id: 'b', state: 'ok' }),
    makeMonitor({ id: 'c', state: 'expiring' }),
    makeMonitor({ id: 'd', state: 'unknown' }),
  ]);
  expect(items).toEqual([]);
});
