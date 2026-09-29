import { Info, OctagonAlert, TriangleAlert, type LucideIcon } from 'lucide-react';
import type { EventKind, Severity } from '@/api/types';
import type { Tone } from './status';

export const KIND_LABEL: Record<EventKind, string> = {
  'cert.issued': 'Certificate issued',
  'cert.renewal_failed': 'Renewal failed',
  'cert.expiring': 'Certificate expiring',
  'cert.expired': 'Certificate expired',
  'deploy.failed': 'Deploy failed',
  'deploy.drift': 'Drift',
  'client.offline': 'Client offline',
  'agent.cert_expiring': 'Agent cert expiring',
  'monitor.mismatch': 'Monitor mismatch',
  'monitor.unreachable': 'Monitor unreachable',
  'monitor.expiring': 'Monitor expiring',
  'monitor.recovered': 'Monitor recovered',
  'backup.completed': 'Backup completed',
  'backup.failed': 'Backup failed',
  test: 'Test',
};

/** Short labels for chips inside a KIND_GROUPS group, where the group name
 * already carries the context the full KIND_LABEL repeats (Deviations). */
export const KIND_SHORT: Record<EventKind, string> = {
  'cert.issued': 'Issued',
  'cert.renewal_failed': 'Renewal failed',
  'cert.expiring': 'Expiring',
  'cert.expired': 'Expired',
  'deploy.failed': 'Failed',
  'deploy.drift': 'Drift',
  'client.offline': 'Offline',
  'agent.cert_expiring': 'Cert expiring',
  'monitor.mismatch': 'Mismatch',
  'monitor.unreachable': 'Unreachable',
  'monitor.expiring': 'Expiring',
  'monitor.recovered': 'Recovered',
  'backup.completed': 'Completed',
  'backup.failed': 'Failed',
  test: 'Test',
};

/** In EventKind enum order (Shared contracts "Enums"). Test is an event
 * filter only, never a channel filter (Deviations, UI conventions). */
export const KIND_GROUPS: { label: string; kinds: EventKind[] }[] = [
  { label: 'Certificates', kinds: ['cert.issued', 'cert.renewal_failed', 'cert.expiring', 'cert.expired'] },
  { label: 'Deployments', kinds: ['deploy.failed', 'deploy.drift'] },
  { label: 'Clients', kinds: ['client.offline', 'agent.cert_expiring'] },
  { label: 'Monitors', kinds: ['monitor.mismatch', 'monitor.unreachable', 'monitor.expiring', 'monitor.recovered'] },
  { label: 'Backups', kinds: ['backup.completed', 'backup.failed'] },
  { label: 'Test', kinds: ['test'] },
];

/** Every kind a channel can be scoped to (ChannelInput.events) — every kind
 * but test, which only ever appears on the events filter. */
export const CHANNEL_KINDS: EventKind[] = KIND_GROUPS.filter((g) => g.label !== 'Test').flatMap((g) => g.kinds);

export const SEVERITY_META: Record<Severity, { label: string; tone: Tone; icon: LucideIcon }> = {
  info: { label: 'Info', tone: 'neutral', icon: Info },
  warning: { label: 'Warning', tone: 'expiring', icon: TriangleAlert },
  critical: { label: 'Critical', tone: 'failed', icon: OctagonAlert },
};

const RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

/** Mirrors internal/notify.SeverityRank: info < warning < critical. */
export function severityRank(s: Severity): number {
  return RANK[s];
}
