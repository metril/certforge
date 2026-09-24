import { expect, it } from 'vitest';
import { iso, makeCert, NOW } from '@/test/fixtures';
import { validityTone } from './status';

it.each([
  ['valid with time to spare', makeCert(), 'valid'],
  ['under 14 days left', makeCert({ currentVersion: { ...makeCert().currentVersion!, notAfter: iso(10) } }), 'expiring'],
  ['renewal overdue', makeCert({ nextRenewAt: iso(-1) }), 'expiring'],
  ['past notAfter', makeCert({ currentVersion: { ...makeCert().currentVersion!, notAfter: iso(-1) } }), 'expired'],
  ['never issued, pending', makeCert({ status: 'pending', currentVersion: undefined }), 'pending'],
  ['never issued, failed', makeCert({ status: 'failed', currentVersion: undefined }), 'failed'],
  // Fix round 1: a revoked cert with a currentVersion whose notAfter is still
  // in the future must not draw as valid.
  ['revoked with a future notAfter', makeCert({ status: 'revoked' }), 'neutral'],
] as const)('%s → %s', (_, cert, tone) => expect(validityTone(cert, NOW)).toBe(tone));
