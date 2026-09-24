import { Ban, CircleAlert, CircleCheck, CircleX, Hourglass, type LucideIcon } from 'lucide-react';
import type { Certificate, CertStatus } from '@/api/types';
import type { HelpKey } from './help';
import { DAY } from './time';

export type Tone = 'valid' | 'expiring' | 'expired' | 'failed' | 'pending' | 'drift' | 'neutral';
export const EXPIRING_DAYS = 14;

export const STATUS_META: Record<CertStatus, { label: string; tone: Tone; icon: LucideIcon; help: HelpKey }> = {
  pending: { label: 'Pending', tone: 'pending', icon: Hourglass, help: 'status.pending' },
  active: { label: 'Active', tone: 'valid', icon: CircleCheck, help: 'status.active' },
  failed: { label: 'Failed', tone: 'failed', icon: CircleAlert, help: 'status.failed' },
  expired: { label: 'Expired', tone: 'expired', icon: CircleX, help: 'status.expired' },
  revoked: { label: 'Revoked', tone: 'neutral', icon: Ban, help: 'status.revoked' },
};

export function validityTone(c: Pick<Certificate, 'status' | 'currentVersion' | 'nextRenewAt'>, now = Date.now()): Tone {
  const v = c.currentVersion;
  if (!v) return c.status === 'failed' ? 'failed' : 'pending';
  const end = Date.parse(v.notAfter);
  if (end <= now) return 'expired';
  if (end - now < EXPIRING_DAYS * DAY) return 'expiring';
  if (c.nextRenewAt && Date.parse(c.nextRenewAt) < now) return 'expiring';
  return 'valid';
}
