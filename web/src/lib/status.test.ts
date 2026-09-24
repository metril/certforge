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
] as const)('%s → %s', (_, cert, tone) => expect(validityTone(cert, NOW)).toBe(tone));
