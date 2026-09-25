import type { EffectiveMap, Source, VerificationMethod, VerificationRule } from '@/api/types';
import { classifyName } from './names';

export type Inherited = { rules: VerificationRule[]; source: Source } | null;
export type CoverageState = 'rule' | 'inherited' | 'missing-credential' | 'ip' | 'none';
export type Coverage = {
  name: string;
  state: CoverageState;
  ruleIndex?: number;
  rule?: VerificationRule;
  source?: Source;
  /** This name is a wildcard whose apex is also on the certificate, so the router's `*.` strip means the apex's rule actually serves it (docs/certificates.md "the rule matching the apex serves both"). */
  viaApex?: boolean;
};

// Adaptation (preflight A31, matcher row): the server (challenge/match.go)
// lowercases and IDNA-normalises both the certificate name and the rule
// pattern to A-labels before comparing. `new URL('http://'+s+'/').hostname`
// runs the same WHATWG host-parsing algorithm (IDNA + lowercasing) that
// jsdom (tr46, in tests) already ships, so it doubles as a zero-dependency
// punycode/IDNA-to-ASCII helper. Falls back to a plain lowercase/trim for
// anything URL can't parse (empty string, ...).
//
// Fix (controller review, Critical #0): jsdom's URL leaves a bare `*`
// untouched, but every real browser's URL/host-parsing (WHATWG-conformant,
// verified against real Chromium) percent-encodes it: `new
// URL('http://*/').hostname === '%2A'`. Run in a real browser (as the
// smoke test does), the old code turned every `*` and `*.zone` rule into
// `%2A`/`%2A.zone`, so no wildcard or catch-all rule ever matched — a
// jsdom-only pass, not a real one. `*` and a leading `*.` are therefore
// stripped before URL-normalising and re-attached after; nothing else
// about a pattern or name legitimately starts with `*` (matchError already
// rejects a `*` anywhere else).
function normaliseAscii(v: string): string {
  try {
    return new URL(`http://${v}/`).hostname.replace(/\.$/, '');
  } catch {
    return v.toLowerCase().replace(/\.$/, '');
  }
}

export function toAscii(s: string): string {
  const v = s.trim();
  if (!v) return '';
  if (v === '*') return '*';
  if (v.startsWith('*.')) return `*.${normaliseAscii(v.slice(2))}`;
  return normaliseAscii(v);
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

// Fix round 1 (review, Important-adjacent): does NOT reuse toAscii(), which
// extracts a URL's `.hostname` and would silently drop anything after the
// first "/" or "@" — exactly the malformed input this must catch. Mirrors
// challenge/match.go's ParseMatch/validZone directly: "*", or an optional
// leading "*." followed by dotted labels of letters, digits, hyphens, and
// underscores only. A label byte above ASCII is tentatively accepted (the
// server would attempt a real IDNA ToASCII conversion first; this has no
// IDNA library, so it defers to the server for genuine Unicode validation
// and only rejects what's unambiguously invalid — ASCII punctuation like
// "/" or "@" that no domain label, Unicode or not, ever contains).
function labelOk(label: string): boolean {
  if (!label) return false;
  for (const ch of label) {
    const c = ch.codePointAt(0)!;
    if (c > 127) continue;
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || c === 45 || c === 95)) return false;
  }
  return true;
}

/** A rule's `match`, validated against the server's own pattern grammar. Returns an error message, or null when valid. */
export function matchError(pattern: string): string | null {
  const raw = pattern.trim().replace(/\.$/, '');
  if (!raw) return 'Required.';
  if (raw === '*') return null;
  const zone = (raw.startsWith('*.') ? raw.slice(2) : raw).toLowerCase();
  const ok = zone !== '' && zone.split('.').every(labelOk);
  return ok ? null : 'Letters, digits, hyphens and underscores only; "*" only as a leading "*.".';
}

const usable = (r: VerificationRule) => r.method !== 'dns-01' || !!r.dnsCredentialId;

export function inheritedFrom(eff: EffectiveMap | undefined): Inherited {
  const e = eff?.verificationRules;
  return e && Array.isArray(e.value) && e.value.length ? { rules: e.value, source: e.source } : null;
}

function resolveName(name: string, rules: VerificationRule[], inherited: Inherited): Coverage {
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
}

export function coverage(names: string[], rules: VerificationRule[], inherited: Inherited): Coverage[] {
  // Fix round 1 (review, Important): the challenge router strips a
  // wildcard name's "*." before routing (docs/certificates.md: "Apex and
  // wildcard ... share `_acme-challenge.example.com`; the rule matching
  // the apex serves both"), so whenever a wildcard's apex is also on the
  // certificate, the two names are proven by the SAME rule — the apex's —
  // not whatever a wildcard's own direct match happens to be. With rules
  // [*.example.com -> B, example.com -> A] the server only ever evaluates
  // "example.com" for both names and gets A; resolving each name
  // independently would show the wildcard as B, a display the runtime
  // never produces.
  const present = new Set(names.map((n) => toAscii(n)));
  return names.map((name): Coverage => {
    if (name.startsWith('*.')) {
      const apex = toAscii(name.slice(2));
      if (present.has(apex)) return { ...resolveName(apex, rules, inherited), name, viaApex: true };
    }
    return resolveName(name, rules, inherited);
  });
}

export const isCovered = (c: Coverage) => c.state === 'rule' || c.state === 'inherited';

export function verificationReady(names: string[], rules: VerificationRule[], inherited: Inherited): boolean {
  return names.length > 0 && rules.every((r) => matchError(r.match) === null) && coverage(names, rules, inherited).every(isCovered);
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
