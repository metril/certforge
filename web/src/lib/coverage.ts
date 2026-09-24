import type { EffectiveMap, Source, VerificationMethod, VerificationRule } from '@/api/types';
import { classifyName } from './names';

export type Inherited = { rules: VerificationRule[]; source: Source } | null;
export type CoverageState = 'rule' | 'inherited' | 'missing-credential' | 'ip' | 'none';
export type Coverage = { name: string; state: CoverageState; ruleIndex?: number; rule?: VerificationRule; source?: Source };

// Adaptation (preflight A31, matcher row): the server (challenge/match.go)
// lowercases and IDNA-normalises both the certificate name and the rule
// pattern to A-labels before comparing. `new URL('http://'+s+'/').hostname`
// runs the same WHATWG host-parsing algorithm (IDNA + lowercasing) that
// jsdom (tr46, in tests) and every real browser already ship, and leaves
// `*` and `_` untouched (neither is a forbidden host code point), so it
// doubles as a zero-dependency punycode/IDNA-to-ASCII helper. Falls back to
// a plain lowercase/trim for anything URL can't parse (empty string, ...).
function toAscii(s: string): string {
  const v = s.trim();
  if (!v) return '';
  try {
    return new URL(`http://${v}/`).hostname.replace(/\.$/, '');
  } catch {
    return v.toLowerCase().replace(/\.$/, '');
  }
}

/** Mirrors the server's matcher (challenge/match.go): first match wins, a
 * `*.zone` rule matches names one label below `zone` and `*.zone` itself, a
 * bare `zone` rule matches the zone, its subdomains, and its wildcard. */
export function matchRule(name: string, pattern: string): boolean {
  const n = toAscii(name);
  const p = toAscii(pattern);
  if (!p) return false;
  if (p === '*') return true;
  if (p.startsWith('*.')) {
    if (n.startsWith('*.')) return n === p;
    const base = p.slice(2);
    return n.endsWith(`.${base}`) && !n.slice(0, -(base.length + 1)).includes('.');
  }
  const bare = n.startsWith('*.') ? n.slice(2) : n;
  return bare === p || bare.endsWith(`.${p}`);
}

const usable = (r: VerificationRule) => r.method !== 'dns-01' || !!r.dnsCredentialId;

export function inheritedFrom(eff: EffectiveMap | undefined): Inherited {
  const e = eff?.verificationRules;
  return e && Array.isArray(e.value) && e.value.length ? { rules: e.value, source: e.source } : null;
}

export function coverage(names: string[], rules: VerificationRule[], inherited: Inherited): Coverage[] {
  return names.map((name): Coverage => {
    if (classifyName(name).kind === 'ip') return { name, state: 'ip' };
    const i = rules.findIndex((r) => matchRule(name, r.match));
    if (i >= 0) {
      const rule = rules[i]!;
      return { name, state: usable(rule) ? 'rule' : 'missing-credential', ruleIndex: i, rule };
    }
    // Adaptation (preflight A31): the server takes the *first* matching
    // rule, full stop — it has no concept of "usable" to skip past. Take
    // only the first inherited match too, rather than searching past an
    // unusable one for a later match that the server would never reach.
    const inh = inherited?.rules.find((r) => matchRule(name, r.match));
    if (inh && inherited) return { name, state: usable(inh) ? 'inherited' : 'missing-credential', rule: inh, source: inherited.source };
    return { name, state: 'none' };
  });
}

export const isCovered = (c: Coverage) => c.state === 'rule' || c.state === 'inherited';

export function verificationReady(names: string[], rules: VerificationRule[], inherited: Inherited): boolean {
  return names.length > 0 && rules.every((r) => r.match.trim() !== '') && coverage(names, rules, inherited).every(isCovered);
}

export function prefillRules(
  names: string[],
  method: VerificationMethod,
  suggest: (zone: string) => string | undefined,
  inherited: Inherited,
): VerificationRule[] {
  const zones: string[] = [];
  for (const n of names) {
    const p = classifyName(n);
    if ((p.kind === 'dns' || p.kind === 'wildcard') && p.zone && !zones.includes(p.zone)) zones.push(p.zone);
  }
  return zones.flatMap((zone): VerificationRule[] => {
    if (method === 'manual-dns') return [{ match: zone, method }];
    const cred = suggest(zone);
    if (cred) return [{ match: zone, method, dnsCredentialId: cred }];
    const inZone = names.filter((n) => classifyName(n).zone === zone);
    // Same first-match fix as coverage() above: a name is covered by the
    // catch-all only if the *first* inherited rule it matches is usable.
    const coveredByInherited =
      !!inherited &&
      inZone.every((n) => {
        const m = inherited.rules.find((r) => matchRule(n, r.match));
        return !!m && usable(m);
      });
    return coveredByInherited ? [] : [{ match: zone, method }];
  });
}
