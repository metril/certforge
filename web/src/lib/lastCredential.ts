import type { Certificate, DnsCredential, VerificationRule } from '@/api/types';
import { matchRule } from './coverage';

const KEY = 'cf-last-cred';

function read(): Record<string, string> {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(KEY) ?? '{}');
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, string>) : {};
  } catch {
    return {};
  }
}

export function rememberCredentials(rules: VerificationRule[]): void {
  const map = read();
  for (const r of rules) if (r.method === 'dns-01' && r.dnsCredentialId && r.match !== '*') map[r.match.replace(/^\*\./, '')] = r.dnsCredentialId;
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
    const s = stored[zone];
    if (s && ids.has(s)) return s;
    for (const c of certs) {
      for (const r of c.verificationRules) {
        if (r.method === 'dns-01' && r.dnsCredentialId && ids.has(r.dnsCredentialId) && r.match !== '*' && matchRule(zone, r.match)) return r.dnsCredentialId;
      }
    }
    return undefined;
  };
}
