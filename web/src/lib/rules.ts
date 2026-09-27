import type { Client, ChallengeVia, DnsCredential, VerificationMethod, VerificationRule } from '@/api/types';
import { pathError } from './paths';

export const METHOD_LABEL: Record<VerificationMethod, string> = {
  'dns-01': 'DNS',
  'manual-dns': 'Manual DNS',
  'http-01': 'HTTP',
  'tls-alpn-01': 'TLS-ALPN',
};

// Context (post-4A review): VerificationRule.via has no schema default, so
// it's sent only for http-01 rules ('server' or 'agent') and omitted for
// every other method — the server ignores it there anyway.

/** Reshapes a rule for a new method, dropping fields the new method has no
 * use for. `match` always survives; a switch to tls-alpn-01 keeps `clientId`
 * only when it's coming from an http-01-via-agent rule (both pick a client
 * the same way). */
export function withMethod(rule: VerificationRule, m: VerificationMethod): VerificationRule {
  switch (m) {
    case 'dns-01':
      return {
        match: rule.match,
        method: m,
        dnsCredentialId: rule.dnsCredentialId,
        propagationSeconds: rule.propagationSeconds,
        resolvers: rule.resolvers,
        cnameAliasZone: rule.cnameAliasZone,
      };
    case 'manual-dns':
      return { match: rule.match, method: m };
    case 'http-01':
      return { match: rule.match, method: m, via: 'server' };
    case 'tls-alpn-01':
      return {
        match: rule.match,
        method: m,
        ...(rule.method === 'http-01' && rule.via === 'agent' && rule.clientId ? { clientId: rule.clientId } : {}),
      };
  }
}

/** Switches an http-01 rule's `via`. Server answers itself and needs
 * neither `clientId` nor `webroot`, so switching to it drops both. */
export function withVia(rule: VerificationRule, via: ChallengeVia): VerificationRule {
  if (via !== 'server') return { ...rule, via };
  const rest: VerificationRule = { ...rule };
  delete rest.clientId;
  delete rest.webroot;
  return { ...rest, via };
}

/** A rule is usable once it has what its method needs to actually run: a
 * credential for dns-01, a client for tls-alpn-01 or http-01 via agent.
 * Everything else (manual-dns, http-01 via server) needs nothing more. */
export function ruleUsable(r: VerificationRule): boolean {
  if (r.method === 'dns-01') return !!r.dnsCredentialId;
  if (r.method === 'http-01') return r.via !== 'agent' || !!r.clientId;
  if (r.method === 'tls-alpn-01') return !!r.clientId;
  return true;
}

/** What actually proves the rule's names: "manual", a credential's name,
 * "server", or a client's name — the fallback strings ("no credential" /
 * "no client") are for an unusable rule, e.g. in a settings summary that
 * doesn't otherwise track usability. */
export function ruleTarget(r: VerificationRule, creds: DnsCredential[], clients: Client[]): string {
  if (r.method === 'manual-dns') return 'manual';
  if (r.method === 'dns-01') return creds.find((c) => c.id === r.dnsCredentialId)?.name ?? 'no credential';
  if (r.method === 'http-01' && r.via !== 'agent') return 'server';
  return clients.find((c) => c.id === r.clientId)?.name ?? 'no client';
}

/** Clients offered for an agent-served challenge: active, and reporting the
 * method's capability — unless it's http-01 with a webroot set, where any
 * active client can write the token file even without its own listener. */
export function clientOptions(clients: Client[], method: 'http-01' | 'tls-alpn-01', webroot?: string): Client[] {
  const active = clients.filter((c) => c.status === 'active');
  if (method === 'http-01' && webroot?.trim()) return active;
  return active.filter((c) => c.capabilities.includes(method));
}

/** Mirrors delivery.CleanPath, same as a layout file's `path` (lib/paths.ts,
 * features/delivery/layoutFiles.ts re-exports the same function). */
export const webrootError = pathError;
