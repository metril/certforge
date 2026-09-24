import { expect, it } from 'vitest';
import { classifyName, groupByZone, splitNames } from './names';

it('splits on commas, spaces, semicolons, and new lines; lowercases; drops trailing dots and duplicates', () => {
  expect(splitNames('A.com, b.com\n\n*.a.com;  a.com.  ')).toEqual(['a.com', 'b.com', '*.a.com']);
});

it.each([
  ['www.example.com', 'dns', 'example.com'],
  ['*.example.com', 'wildcard', 'example.com'],
  ['a.b.example.co.uk', 'dns', 'example.co.uk'],
  ['lab.local', 'dns', 'lab.local'],
  ['192.0.2.10', 'ip', null],
  ['255.255.255.255', 'ip', null],
  ['2001:db8::1', 'ip', null],
  ['::1', 'ip', null],
  ['fe80::1', 'ip', null],
  ['2001:db8:85a3::8a2e:370:7334', 'ip', null],
  ['::ffff:192.0.2.1', 'ip', null],
  ['localhost', 'invalid', null],
  ['*.com', 'invalid', null],
  ['*.co.uk', 'invalid', null],
  ['a.*.example.com', 'invalid', null],
  ['bad_name.example.com', 'invalid', null],
  ['-edge.example.com', 'invalid', null],
  // Fix round 1 (review, Important #1): the client's IP check was looser
  // than the server's `net.ParseIP` — these four look IP-shaped but fail
  // strict validation (out-of-range octet, too few IPv6 groups, doubled
  // "::", and an IPv6 zone id `net.ParseIP` doesn't accept) and must not
  // classify as 'ip' (which would enable Next and then be rejected server
  // side).
  ['999.1.1.1', 'invalid', null],
  ['dead:beef', 'invalid', null],
  ['::::', 'invalid', null],
  ['fe80::1%eth0', 'invalid', null],
  // Fix round 1 (review, Important #4): the server's own name validator
  // (internal/issuance/names.go) has no public-suffix awareness — it only
  // requires a dotted, syntactically valid FQDN — so a wildcard whose zone
  // is a "private" PSL entry that is itself registrable (github.io, unlike
  // a plain ICANN suffix like co.uk, which stays invalid above) must not be
  // rejected client-side either.
  ['*.github.io', 'wildcard', 'github.io'],
])('classifies %s as %s', (v, kind, zone) => {
  const p = classifyName(v);
  expect(p.kind).toBe(kind);
  expect(p.zone).toBe(zone);
  if (kind === 'invalid') expect(p.error).toBeTruthy();
});

it('groups by registered domain in first-seen order, with IPs and invalid names last', () => {
  const groups = groupByZone(['b.other.net', 'www.example.com', '10.0.0.1', 'bad_x.example.com', '*.example.com'].map(classifyName));
  expect(groups.map((g) => [g.zone, g.names.length])).toEqual([
    ['other.net', 1],
    ['example.com', 2],
    ['IP addresses', 1],
    ['Invalid', 1],
  ]);
});

// Controller ruling (docs/design.md "Certificate create wizard"): grouping
// must cover a private zone (a `lab.local`-style TLD absent from the public
// suffix list) grouping under itself, not just public-suffix zones.
it('groups a private zone (lab.local) under itself, alongside a public one', () => {
  const groups = groupByZone(['db.lab.local', 'lab.local', 'a.example.com'].map(classifyName));
  expect(groups.map((g) => [g.zone, g.names.length])).toEqual([
    ['lab.local', 2],
    ['example.com', 1],
  ]);
});

it('parses 200 names quickly', () => {
  const text = Array.from({ length: 220 }, (_, i) => `host${i % 200}.zone${(i % 200) % 7}.example`).join('\n');
  const t0 = performance.now();
  const parsed = splitNames(text).map(classifyName);
  expect(parsed).toHaveLength(200);
  expect(performance.now() - t0).toBeLessThan(100);
});
