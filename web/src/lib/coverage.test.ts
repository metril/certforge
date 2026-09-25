import { expect, it } from 'vitest';
import { coverage, matchError, matchRule, prefillRules, toAscii, verificationReady } from './coverage';

it.each([
  ['www.example.com', 'example.com', true],
  ['example.com', 'example.com', true],
  ['*.example.com', 'example.com', true],
  ['notexample.com', 'example.com', false],
  ['a.example.com', '*.example.com', true],
  ['a.b.example.com', '*.example.com', false],
  ['*.example.com', '*.example.com', true],
  ['*.a.example.com', '*.example.com', false],
  ['anything.test', '*', true],
  ['EXAMPLE.com.', 'example.com', true],
  // IDNA: a Unicode name and a punycode pattern (or vice versa) for the
  // same zone normalise to the same A-label and match, mirroring the
  // server's idna.Lookup.ToASCII normalization (preflight A31).
  ['xn--bcher-kva.example.com', 'bücher.example.com', true],
  ['bücher.example.com', 'xn--bcher-kva.example.com', true],
])('matchRule(%s, %s) = %s', (name, pattern, expected) => expect(matchRule(name, pattern)).toBe(expected));

it.each([
  ['*', true],
  ['example.com', true],
  ['*.example.com', true],
  ['a-b_c.example.com', true],
  ['example.com/foo', false],
  ['a@b.com', false],
  ['', false],
  // Mirrors challenge/match.go's normalize(): a lone trailing dot is
  // stripped before the "*" check, so "*." is just "*" (valid), same as a
  // trailing-dot zone name is just that zone.
  ['*.', true],
])('matchError(%s) valid = %s', (pattern, valid) => expect(matchError(pattern) === null).toBe(valid));

// Controller review, Critical #0: jsdom's URL leaves a bare `*` alone, but
// every real browser's WHATWG host parser percent-encodes it (verified
// against real Chromium: `new URL('http://*/').hostname === '%2A'`), which
// used to turn every `*`/`*.zone` rule into an unmatchable `%2A`/`%2A.zone`
// — a jsdom-only pass, not a real one. This stubs a Chromium-parity URL
// (lowercases the host and percent-encodes `*`, like a real browser) so the
// test fails the same way a real browser would if the `*`/`*.` special
// case in toAscii() were ever removed.
it('toAscii and matchRule still treat "*" as a wildcard under a Chromium-parity URL (percent-encodes *)', () => {
  const OriginalURL = globalThis.URL;
  class ChromiumLikeURL {
    hostname: string;
    constructor(input: string) {
      const host = input.slice('http://'.length, -1);
      this.hostname = host.toLowerCase().replace(/\*/g, '%2A');
    }
  }
  // @ts-expect-error -- minimal stub of the WHATWG URL constructor for this test only
  globalThis.URL = ChromiumLikeURL;
  try {
    expect(toAscii('*')).toBe('*');
    expect(toAscii('*.Example.test')).toBe('*.example.test');
    expect(matchRule('smoke.example.test', '*')).toBe(true);
  } finally {
    globalThis.URL = OriginalURL;
  }
});

const names = ['www.example.com', '*.example.com', 'api.other.net', '10.0.0.1'];

it('reports first-match rules, missing credentials, inherited catch-all, and IPs', () => {
  const c = coverage(names, [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }, { match: 'other.net', method: 'dns-01' }], null);
  expect(c.map((x) => x.state)).toEqual(['rule', 'rule', 'missing-credential', 'ip']);
  const inh = { rules: [{ match: '*', method: 'dns-01' as const, dnsCredentialId: 'd-2' }], source: 'org' as const };
  expect(coverage(['api.other.net'], [], inh)[0]).toMatchObject({ state: 'inherited', source: 'org' });
  expect(verificationReady(['api.other.net'], [], inh)).toBe(true);
  expect(verificationReady(['api.other.net'], [], null)).toBe(false);
});

// Fix round 1 (review, Important): the router strips a wildcard name's
// "*." before routing, so the apex's rule serves both names whenever the
// apex is also on the certificate (docs/certificates.md "the rule matching
// the apex serves both") — not whatever the wildcard's own direct match
// happens to be.
it('routes a wildcard through its apex rule when the apex is also on the certificate', () => {
  const rules = [
    { match: '*.example.com', method: 'dns-01' as const, dnsCredentialId: 'd-2' },
    { match: 'example.com', method: 'dns-01' as const, dnsCredentialId: 'd-1' },
  ];
  const c = coverage(['example.com', '*.example.com'], rules, null);
  expect(c[0]).toMatchObject({ name: 'example.com', state: 'rule', ruleIndex: 1 });
  expect(c[0]!.viaApex).toBeUndefined();
  expect(c[1]).toMatchObject({ name: '*.example.com', state: 'rule', ruleIndex: 1, viaApex: true });
});

it('a wildcard whose apex is NOT on the certificate uses its own rule', () => {
  const rules = [
    { match: '*.example.com', method: 'dns-01' as const, dnsCredentialId: 'd-2' },
    { match: 'example.com', method: 'dns-01' as const, dnsCredentialId: 'd-1' },
  ];
  const c = coverage(['*.example.com'], rules, null);
  expect(c[0]).toMatchObject({ name: '*.example.com', state: 'rule', ruleIndex: 0 });
  expect(c[0]!.viaApex).toBeUndefined();
});

it('an invalid match pattern blocks verificationReady even when coverage would otherwise pass', () => {
  const rules = [{ match: 'example.com/oops', method: 'dns-01' as const, dnsCredentialId: 'd-1' }];
  expect(verificationReady(['a.example.com'], rules, null)).toBe(false);
});

it('prefills one rule per zone, never guesses a credential, and leans on a catch-all', () => {
  const suggest = (z: string) => (z === 'example.com' ? 'd-1' : undefined);
  expect(prefillRules(names, 'dns-01', suggest, null)).toEqual([
    { match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' },
    { match: 'other.net', method: 'dns-01' },
  ]);
  const inh = { rules: [{ match: '*', method: 'dns-01' as const, dnsCredentialId: 'd-2' }], source: 'org' as const };
  expect(prefillRules(names, 'dns-01', suggest, inh)).toEqual([{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }]);
  expect(prefillRules(names, 'manual-dns', suggest, null)).toEqual([
    { match: 'example.com', method: 'manual-dns' },
    { match: 'other.net', method: 'manual-dns' },
  ]);
});
