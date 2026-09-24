import { parse } from 'tldts';

export const MAX_NAMES = 100;

export type NameKind = 'dns' | 'wildcard' | 'ip' | 'invalid';
export type ParsedName = { value: string; kind: NameKind; zone: string | null; error?: string };
export type NameGroup = { zone: string; kind: 'zone' | 'ip' | 'invalid'; names: ParsedName[] };

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
// Loose "looks like an IP attempt" shapes, used only to pick a clearer error
// message for a near-miss than the generic DNS-label one.
const IPV4_SHAPE = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_SHAPE = /^[0-9a-f:]+(%.+)?$/i;

// Fix round 1 (review, Important #1): mirrors Go's `net.ParseIP` exactly
// (verified empirically against it) rather than tldts's looser `isIp`,
// which accepts out-of-range octets, malformed IPv6, and zone ids the
// server's `net.ParseIP` rejects.
function isIPv4(s: string): boolean {
  const parts = s.split('.');
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p.length === 1 || p[0] !== '0'));
}

function isIPv6(s: string): boolean {
  if (!s.includes(':') || s.includes('%')) return false;
  if (s.split('::').length > 2) return false;
  const compressed = s.includes('::');
  const lastColon = s.lastIndexOf(':');
  const afterLast = s.slice(lastColon + 1);
  let ipv4Groups = 0;
  let head = s;
  if (afterLast.includes('.')) {
    if (!isIPv4(afterLast)) return false;
    ipv4Groups = 2;
    head = s.slice(0, lastColon + 1);
    if (!head.endsWith('::')) head = head.slice(0, -1);
  }
  const parts = compressed ? head.split('::') : [head];
  const groups = parts.flatMap((p) => (p ? p.split(':') : []));
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false;
  const total = groups.length + ipv4Groups;
  return compressed ? total < 8 : total === 8;
}

export function splitNames(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of text.split(/[\s,;]+/)) {
    const v = raw.trim().toLowerCase().replace(/\.$/, '');
    if (v && !seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  }
  return out;
}

const invalid = (value: string, error: string): ParsedName => ({ value, kind: 'invalid', zone: null, error });

export function classifyName(value: string): ParsedName {
  if (isIPv4(value) || isIPv6(value)) return { value, kind: 'ip', zone: null };
  if (IPV4_SHAPE.test(value)) return invalid(value, 'Not a valid IPv4 address: each part must be 0-255');
  if (value.includes(':') && IPV6_SHAPE.test(value)) {
    return invalid(value, value.includes('%') ? 'IPv6 zone ids, like %eth0, are not supported' : 'Not a valid IPv6 address');
  }
  const wildcard = value.startsWith('*.');
  const host = wildcard ? value.slice(2) : value;
  if (host.includes('*')) return invalid(value, 'Wildcard only as the first label, like *.example.com');
  if (host.length > 253) return invalid(value, 'Longer than 253 characters');
  const labels = host.split('.');
  if (labels.length < 2) return invalid(value, 'Needs a domain, like host.example.com');
  if (!labels.every((l) => LABEL.test(l))) return invalid(value, 'Letters, digits, and hyphens only; use xn-- for IDNs');
  const parsed = parse(host, { allowPrivateDomains: true });
  // Fix round 1 (review, Important #4): the server's own validator has no
  // public-suffix list at all, so it accepts any dotted, syntactically
  // valid FQDN regardless of whether tldts considers it "registrable". A
  // bare ICANN suffix (co.uk, com — `isPrivate: false`) stays invalid: it's
  // never anyone's zone to control. A "private" PSL entry (github.io,
  // herokuapp.com — `isPrivate: true`) is itself the registrable unit third
  // parties get subdomains under, matching what the server would accept;
  // group it under itself, the same way an unknown-TLD private zone
  // (lab.local) already groups under itself below.
  const zone = parsed.domain ?? (parsed.isPrivate ? host : null);
  if (!zone) return invalid(value, 'Not under a registrable domain');
  return { value, kind: wildcard ? 'wildcard' : 'dns', zone };
}

export function groupByZone(names: ParsedName[]): NameGroup[] {
  const zones = new Map<string, ParsedName[]>();
  const ips: ParsedName[] = [];
  const bad: ParsedName[] = [];
  for (const n of names) {
    if (n.kind === 'ip') ips.push(n);
    else if (n.kind === 'invalid' || !n.zone) bad.push(n);
    else zones.set(n.zone, [...(zones.get(n.zone) ?? []), n]);
  }
  const out: NameGroup[] = [...zones].map(([zone, list]) => ({ zone, kind: 'zone' as const, names: list }));
  if (ips.length) out.push({ zone: 'IP addresses', kind: 'ip', names: ips });
  if (bad.length) out.push({ zone: 'Invalid', kind: 'invalid', names: bad });
  return out;
}
