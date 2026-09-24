import type { Certificate, DnsCredential, VerificationRule } from '@/api/types';
import { matchRule, toAscii } from './coverage';

const KEY = 'cf-last-cred';

function read(): Record<string, string> {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(KEY) ?? '{}');
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, string>) : {};
  } catch {
    return {};
  }
}

/**
 * Remembers, per normalised (lowercase, IDNA A-label) zone, the credential a
 * rule used. Fix round 1 (review): called once by the caller after a
 * certificate is actually created (Task 14), not on every keystroke while
 * editing rules — that would write a junk key per character typed into the
 * match field.
 */
export function rememberFromRules(rules: VerificationRule[]): void {
  const map = read();
  for (const r of rules) {
    if (r.method !== 'dns-01' || !r.dnsCredentialId || r.match === '*') continue;
    const zone = toAscii(r.match.replace(/^\*\./, ''));
    if (zone) map[zone] = r.dnsCredentialId;
  }
  try {
    localStorage.setItem(KEY, JSON.stringify(map));
  } catch {
    // Storage blocked: suggestions fall back to existing certificates.
  }
}

export function makeSuggester(certs: Certificate[], creds: DnsCredential[]) {
  const ids = new Set(creds.map((c) => c.id));
  const stored = read();
  return (zone: string): string | undefined => {
    const s = stored[toAscii(zone)];
    if (s && ids.has(s)) return s;
    for (const c of certs) {
      for (const r of c.verificationRules) {
        if (r.method === 'dns-01' && r.dnsCredentialId && ids.has(r.dnsCredentialId) && r.match !== '*' && matchRule(zone, r.match)) return r.dnsCredentialId;
      }
    }
    return undefined;
  };
}
