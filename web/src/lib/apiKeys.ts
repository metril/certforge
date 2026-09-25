import type { ApiKey, Me } from '@/api/types';

// Shared by BindingSheet (the apikey subject picker) and ApiKeysTab (the
// list, create sheet, and cards) — pulled out of both so neither imports
// the other (fix round 1: the two used to import from each other).
export const GLOBAL = 'global';

export function scopeLabel(me: Pick<Me, 'orgs'>, orgId: string | null): string {
  return orgId === null ? 'All orgs' : (me.orgs.find((o) => o.id === orgId)?.name ?? orgId);
}

/** `now` defaults to the real clock; a fixed value keeps this pure for tests.
 * An `expiresAt` exactly at `now` counts as expired, not active (`<=`). */
export function keyState(k: Pick<ApiKey, 'revokedAt' | 'expiresAt'>, fixedNow = Date.now()): 'active' | 'expired' | 'revoked' {
  if (k.revokedAt) return 'revoked';
  if (k.expiresAt && Date.parse(k.expiresAt) <= fixedNow) return 'expired';
  return 'active';
}
