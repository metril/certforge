import { describe, expect, it } from 'vitest';
import type { EventKind } from '@/api/types';
import { CHANNEL_KINDS, KIND_GROUPS, KIND_LABEL, KIND_SHORT, SEVERITY_META, severityRank } from './events';

const ALL_KINDS: EventKind[] = [
  'cert.issued', 'cert.renewal_failed', 'cert.expiring', 'cert.expired',
  'deploy.failed', 'deploy.drift',
  'client.offline', 'agent.cert_expiring', 'client.pending_approval',
  'monitor.mismatch', 'monitor.unreachable', 'monitor.expiring', 'monitor.recovered',
  'backup.completed', 'backup.failed',
  'test',
];

it('every EventKind has a label and a group', () => {
  const grouped = KIND_GROUPS.flatMap((g) => g.kinds);
  for (const kind of ALL_KINDS) {
    expect(KIND_LABEL[kind]).toBeTruthy();
    expect(KIND_SHORT[kind]).toBeTruthy();
    expect(grouped).toContain(kind);
  }
  expect(grouped).toHaveLength(ALL_KINDS.length);
});

it('channel kinds exclude test', () => {
  expect(CHANNEL_KINDS).not.toContain('test');
  expect(CHANNEL_KINDS).toHaveLength(ALL_KINDS.length - 1);
});

describe('severity rank order', () => {
  it('orders info < warning < critical', () => {
    expect(severityRank('info')).toBeLessThan(severityRank('warning'));
    expect(severityRank('warning')).toBeLessThan(severityRank('critical'));
  });

  it('every severity has meta', () => {
    expect(SEVERITY_META.info.label).toBe('Info');
    expect(SEVERITY_META.warning.label).toBe('Warning');
    expect(SEVERITY_META.critical.label).toBe('Critical');
  });
});
