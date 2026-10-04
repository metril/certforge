import { Ban, CircleAlert, CircleCheck, CircleX, Hourglass, type LucideIcon } from 'lucide-react';
import type { CertBrief, Certificate, CertStatus } from '@/api/types';
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

export function validityTone(c: Pick<CertBrief, 'status' | 'notAfter' | 'nextRenewAt'>, now = Date.now()): Tone {
  // Fix round 1: a revoked certificate can still have a currentVersion whose
  // notAfter is in the future; without this it fell through to the time
  // checks below and drew a green/valid bar.
  if (c.status === 'revoked') return 'neutral';
  if (!c.notAfter) return c.status === 'failed' ? 'failed' : 'pending';
  const end = Date.parse(c.notAfter);
  if (end <= now) return 'expired';
  if (end - now < EXPIRING_DAYS * DAY) return 'expiring';
  if (c.nextRenewAt && Date.parse(c.nextRenewAt) < now) return 'expiring';
  return 'valid';
}

/** validityTone for a full certificate. */
export const certTone = (c: Pick<Certificate, 'status' | 'currentVersion' | 'nextRenewAt'>, now = Date.now()): Tone =>
  validityTone({ status: c.status, notAfter: c.currentVersion?.notAfter ?? null, nextRenewAt: c.nextRenewAt }, now);
