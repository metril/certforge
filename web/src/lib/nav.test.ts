import { expect, it } from 'vitest';
import { isNavPathActive } from './nav';

// Fix round 1 (review): a raw `pathname.startsWith(prefix)` lit up
// Certificates for "/o/acme/certificates-foo" and couldn't light up
// Settings for any section but the literal one its Link resolves to.
// `renderRoute('/o/acme/certificates-foo')` can't exercise this end to
// end — that path isn't a registered route, so it 404s at the router
// root before AppShell ever mounts — so this checks the matcher directly.
it('matches the prefix itself and any path segment below it', () => {
  expect(isNavPathActive('/settings', '/settings')).toBe(true);
  expect(isNavPathActive('/settings/tls', '/settings')).toBe(true);
  expect(isNavPathActive('/settings/general/sub', '/settings')).toBe(true);
});

it('does not match a sibling path that merely starts with the same characters', () => {
  expect(isNavPathActive('/o/acme/certificates-foo', '/o/acme/certificates')).toBe(false);
  expect(isNavPathActive('/o/acme/certificatesx', '/o/acme/certificates')).toBe(false);
});

it('does not match an unrelated path', () => {
  expect(isNavPathActive('/o/acme/issuers', '/o/acme/certificates')).toBe(false);
});
