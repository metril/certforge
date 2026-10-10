import { describe, expect, it } from 'vitest';
import type { Client } from '@/api/types';
import { makeClient } from '@/test/fixtures';
import { coverage, matchError, matchRule, prefillRules, toAscii, verificationReady } from './coverage';

const noClients: Client[] = [];

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

it('reports first-match rules, incomplete rules, inherited catch-all, and IPs', () => {
  const c = coverage(
    names,
    [
      { match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' },
      { match: 'other.net', method: 'dns-01' },
    ],
    null,
    noClients,
  );
  expect(c.map((x) => x.state)).toEqual(['rule', 'rule', 'incomplete', 'ip']);
  const inh = { rules: [{ match: '*', method: 'dns-01' as const, dnsCredentialId: 'd-2' }], source: 'org' as const };
  expect(coverage(['api.other.net'], [], inh, noClients)[0]).toMatchObject({ state: 'inherited', source: 'org' });
  expect(verificationReady(['api.other.net'], [], inh, noClients)).toBe(true);
  expect(verificationReady(['api.other.net'], [], null, noClients)).toBe(false);
});

// Context (post-4A review): the server rejects a wildcard's http-01/tls-
// alpn-01 rule the same way it rejects no match at all, falling through to
// the next rule — a wildcard can never be covered by either method.
it('a wildcard resolving only to an http-01 or tls-alpn-01 rule is "wildcard-non-dns", not covered', () => {
  const rules = [{ match: '*.a.test', method: 'http-01' as const, via: 'server' as const }];
  const c = coverage(['*.a.test'], rules, null, noClients);
  expect(c[0]).toMatchObject({ name: '*.a.test', state: 'wildcard-non-dns' });
  expect(verificationReady(['*.a.test'], rules, null, noClients)).toBe(false);
});

it('a wildcard falls through a skipped http-01 rule to a later dns-01 rule', () => {
  const rules = [
    { match: '*.a.test', method: 'http-01' as const, via: 'server' as const },
    { match: 'a.test', method: 'dns-01' as const, dnsCredentialId: 'd-1' },
  ];
  const c = coverage(['*.a.test'], rules, null, noClients);
  expect(c[0]).toMatchObject({ name: '*.a.test', state: 'rule', ruleIndex: 1 });
});

it('an http-01 rule via agent needs a client that reports the capability', () => {
  const rules = [{ match: 'a.test', method: 'http-01' as const, via: 'agent' as const }];
  expect(coverage(['a.test'], rules, null, noClients)[0]).toMatchObject({ state: 'incomplete' });
  const withClient = [{ match: 'a.test', method: 'http-01' as const, via: 'agent' as const, clientId: 'c-1' }];
  const capable = [makeClient({ id: 'c-1', status: 'active', capabilities: ['http-01'] })];
  expect(coverage(['a.test'], withClient, null, capable)[0]).toMatchObject({ state: 'rule' });
});

it('a tls-alpn-01 rule with no client is incomplete', () => {
  const rules = [{ match: 'a.test', method: 'tls-alpn-01' as const }];
  expect(coverage(['a.test'], rules, null, noClients)[0]).toMatchObject({ state: 'incomplete' });
});

it('mixed methods are each covered by their own rule', () => {
  const rules = [
    { match: 'a.test', method: 'dns-01' as const, dnsCredentialId: 'd-1' },
    { match: 'b.test', method: 'http-01' as const, via: 'server' as const },
    { match: 'c.test', method: 'tls-alpn-01' as const, clientId: 'c-1' },
  ];
  const clients = [makeClient({ id: 'c-1', status: 'active', capabilities: ['tls-alpn-01'] })];
  const c = coverage(['a.test', 'b.test', 'c.test'], rules, null, clients);
  expect(c.map((x) => x.state)).toEqual(['rule', 'rule', 'rule']);
  expect(verificationReady(['a.test', 'b.test', 'c.test'], rules, null, clients)).toBe(true);
});

// Controller ruling (review fix round 2): clients thread all the way
// through coverage()/resolveName()/verificationReady() now, so an
// agent-mode rule's clientId is checked against the same capability
// (clientOptions()) the picker itself enforces — not just its presence —
// exactly like a dns-01 rule with a dangling/missing credential.
describe('an agent-mode rule is only covered when its client actually qualifies', () => {
  const noCap = [makeClient({ id: 'c-1', status: 'active', capabilities: [] })];
  const capableHttp = [makeClient({ id: 'c-1', status: 'active', capabilities: ['http-01'] })];
  const capableAlpn = [makeClient({ id: 'c-1', status: 'active', capabilities: ['tls-alpn-01'] })];

  it('http-01 via agent: a client with no capability and no webroot is incomplete', () => {
    const rules = [{ match: 'a.test', method: 'http-01' as const, via: 'agent' as const, clientId: 'c-1' }];
    expect(coverage(['a.test'], rules, null, noCap)[0]).toMatchObject({ state: 'incomplete' });
    expect(verificationReady(['a.test'], rules, null, noCap)).toBe(false);
  });

  it('http-01 via agent: the same client and rule are covered once a webroot is set', () => {
    const rules = [{ match: 'a.test', method: 'http-01' as const, via: 'agent' as const, clientId: 'c-1', webroot: '/srv/acme' }];
    expect(coverage(['a.test'], rules, null, noCap)[0]).toMatchObject({ state: 'rule' });
    expect(verificationReady(['a.test'], rules, null, noCap)).toBe(true);
  });

  it('http-01 via agent: a capable client is covered with no webroot needed', () => {
    const rules = [{ match: 'a.test', method: 'http-01' as const, via: 'agent' as const, clientId: 'c-1' }];
    expect(coverage(['a.test'], rules, null, capableHttp)[0]).toMatchObject({ state: 'rule' });
  });

  it('tls-alpn-01: a client with no capability is incomplete; a capable one is covered', () => {
    const rules = [{ match: 'a.test', method: 'tls-alpn-01' as const, clientId: 'c-1' }];
    expect(coverage(['a.test'], rules, null, noCap)[0]).toMatchObject({ state: 'incomplete' });
    expect(coverage(['a.test'], rules, null, capableAlpn)[0]).toMatchObject({ state: 'rule' });
  });
});

// Review fix round 1 (Important): the apex-sharing shortcut only holds for
// dns-01/manual-dns; an apex's own http-01 rule can win the apex's lookup
// (the apex itself is never skipped) but can never prove the wildcard, so
// the wildcard must fall back to resolving itself instead of being marked
// "covered" by a rule that can't cover it.
it('an apex http-01 rule does not cover its wildcard; a later dns-01 rule matching the wildcard directly does', () => {
  const rules = [
    { match: 'example.com', method: 'http-01' as const, via: 'server' as const },
    { match: '*.example.com', method: 'dns-01' as const, dnsCredentialId: 'd-1' },
  ];
  const c = coverage(['example.com', '*.example.com'], rules, null, noClients);
  expect(c[0]).toMatchObject({ name: 'example.com', state: 'rule', ruleIndex: 0 });
  expect(c[1]).toMatchObject({ name: '*.example.com', state: 'rule', ruleIndex: 1 });
  expect(c[1]!.viaApex).toBeUndefined();
});

it('an apex http-01 rule with no other rule leaves the wildcard "wildcard-non-dns"', () => {
  const rules = [{ match: 'example.com', method: 'http-01' as const, via: 'server' as const }];
  const c = coverage(['example.com', '*.example.com'], rules, null, noClients);
  expect(c[0]).toMatchObject({ name: 'example.com', state: 'rule', ruleIndex: 0 });
  expect(c[1]).toMatchObject({ name: '*.example.com', state: 'wildcard-non-dns' });
  expect(c[1]!.viaApex).toBeUndefined();
});

// Fix round 1 (review, Important): the router strips a wildcard name's
// "*." before routing, so the apex's rule serves both names whenever the
// apex is also on the certificate (docs/guide/certificates.md "the rule matching
// the apex serves both") — not whatever the wildcard's own direct match
// happens to be.
it('routes a wildcard through its apex rule when the apex is also on the certificate', () => {
  const rules = [
    { match: '*.example.com', method: 'dns-01' as const, dnsCredentialId: 'd-2', via: 'server' as const },
    { match: 'example.com', method: 'dns-01' as const, dnsCredentialId: 'd-1', via: 'server' as const },
  ];
  const c = coverage(['example.com', '*.example.com'], rules, null, noClients);
  expect(c[0]).toMatchObject({ name: 'example.com', state: 'rule', ruleIndex: 1 });
  expect(c[0]!.viaApex).toBeUndefined();
  expect(c[1]).toMatchObject({ name: '*.example.com', state: 'rule', ruleIndex: 1, viaApex: true });
});

it('a wildcard whose apex is NOT on the certificate uses its own rule', () => {
  const rules = [
    { match: '*.example.com', method: 'dns-01' as const, dnsCredentialId: 'd-2', via: 'server' as const },
    { match: 'example.com', method: 'dns-01' as const, dnsCredentialId: 'd-1', via: 'server' as const },
  ];
  const c = coverage(['*.example.com'], rules, null, noClients);
  expect(c[0]).toMatchObject({ name: '*.example.com', state: 'rule', ruleIndex: 0 });
  expect(c[0]!.viaApex).toBeUndefined();
});

it('an invalid match pattern blocks verificationReady even when coverage would otherwise pass', () => {
  const rules = [{ match: 'example.com/oops', method: 'dns-01' as const, dnsCredentialId: 'd-1', via: 'server' as const }];
  expect(verificationReady(['a.example.com'], rules, null, noClients)).toBe(false);
});

it('prefills one dns-01 rule per zone, never guesses a credential, and leans on a catch-all', () => {
  const suggest = (z: string) => (z === 'example.com' ? 'd-1' : undefined);
  expect(prefillRules(names, suggest, null, noClients)).toEqual([
    { match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' },
    { match: 'other.net', method: 'dns-01' },
  ]);
  const inh = { rules: [{ match: '*', method: 'dns-01' as const, dnsCredentialId: 'd-2' }], source: 'org' as const };
  expect(prefillRules(names, suggest, inh, noClients)).toEqual([{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }]);
});
