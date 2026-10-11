import { Globe, Landmark, Server, Vault, type LucideIcon } from 'lucide-react';
import type { CA, CaType } from '@/api/types';
import { EXPIRING_DAYS, type Tone } from './status';
import { DAY } from './time';

/** Deviations R4 / UI conventions: display names for each CA kind. */
export const KIND_LABEL: Record<CaType, string> = {
  acme: 'ACME',
  localca: 'Built-in CA',
  vaultpki: 'Vault PKI',
  adcs: 'AD CS',
};

/** The Type picker's longer labels (the list and chips use KIND_LABEL). */
export const KIND_FULL_LABEL: Record<CaType, string> = { ...KIND_LABEL, adcs: 'Active Directory (AD CS)' };

/** UI conventions: the Type chip's icon per kind, shared by the CAs list
 * and the private CA detail sheet (task 3). */
export const KIND_ICON: Record<CaType, LucideIcon> = { acme: Globe, localca: Landmark, vaultpki: Vault, adcs: Server };

/** The CA's kind, defaulting to acme when the CA itself isn't known yet
 * (a new-CA sheet before the operator picks a kind). */
export function kindOf(ca?: Pick<CA, 'type'>): CaType {
  return ca?.type ?? 'acme';
}

/** Every kind but acme is a private CA (no ACME account or directory). */
export function isPrivate(ca: Pick<CA, 'type'>): boolean {
  return kindOf(ca) !== 'acme';
}

/** The CA's current CRL, if it publishes one (localca with crl enabled and
 * general.baseUrl set); no serial argument — this is always the current
 * issuer's CRL, never a retired one's (those come from CA.config.retired). */
export function crlUrlFor(ca: Pick<CA, 'crlUrl'>): string | undefined {
  return ca.crlUrl;
}

/** Tone for a private CA's issuing-certificate expiry, same thresholds as
 * a certificate's own validity bar; neutral when there's nothing to show
 * (acme, or a CA not yet loaded). */
export function caTone(notAfter: string | undefined, now = Date.now()): Tone {
  if (!notAfter) return 'neutral';
  const end = Date.parse(notAfter);
  if (end <= now) return 'expired';
  if (end - now < EXPIRING_DAYS * DAY) return 'expiring';
  return 'valid';
}
