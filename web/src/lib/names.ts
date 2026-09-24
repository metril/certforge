import { parse } from 'tldts';

export const MAX_NAMES = 100;

export type NameKind = 'dns' | 'wildcard' | 'ip' | 'invalid';
export type ParsedName = { value: string; kind: NameKind; zone: string | null; error?: string };
export type NameGroup = { zone: string; kind: 'zone' | 'ip' | 'invalid'; names: ParsedName[] };

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const IPV6 = /^[0-9a-f:]+(%\w+)?$/i;

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
  if (value.includes(':') && IPV6.test(value)) return { value, kind: 'ip', zone: null };
  if (parse(value).isIp) return { value, kind: 'ip', zone: null };
  const wildcard = value.startsWith('*.');
  const host = wildcard ? value.slice(2) : value;
  if (host.includes('*')) return invalid(value, 'Wildcard only as the first label, like *.example.com');
  if (host.length > 253) return invalid(value, 'Longer than 253 characters');
  const labels = host.split('.');
  if (labels.length < 2) return invalid(value, 'Needs a domain, like host.example.com');
  if (!labels.every((l) => LABEL.test(l))) return invalid(value, 'Letters, digits, and hyphens only; use xn-- for IDNs');
  const zone = parse(host, { allowPrivateDomains: true }).domain;
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
