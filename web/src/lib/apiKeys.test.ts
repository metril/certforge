import { expect, it } from 'vitest';
import { keyState } from './apiKeys';

const NOW = Date.parse('2026-09-24T12:00:00Z');

it('is revoked when revokedAt is set, regardless of expiry', () => {
  expect(keyState({ revokedAt: '2026-01-01T00:00:00Z', expiresAt: null }, NOW)).toBe('revoked');
  expect(keyState({ revokedAt: '2026-01-01T00:00:00Z', expiresAt: '2099-01-01T00:00:00Z' }, NOW)).toBe('revoked');
});

it('is active with no expiry and no revocation', () => {
  expect(keyState({ revokedAt: null, expiresAt: null }, NOW)).toBe('active');
});

it('is active while expiresAt is in the future', () => {
  expect(keyState({ revokedAt: null, expiresAt: new Date(NOW + 1).toISOString() }, NOW)).toBe('active');
});

it('is expired once expiresAt has passed', () => {
  expect(keyState({ revokedAt: null, expiresAt: new Date(NOW - 1).toISOString() }, NOW)).toBe('expired');
});

it('treats expiresAt exactly equal to now as expired (boundary)', () => {
  expect(keyState({ revokedAt: null, expiresAt: new Date(NOW).toISOString() }, NOW)).toBe('expired');
});

it('defaults fixedNow to the real clock', () => {
  expect(keyState({ revokedAt: null, expiresAt: null })).toBe('active');
});
