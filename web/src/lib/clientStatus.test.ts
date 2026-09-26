import { describe, expect, it } from 'vitest';
import { iso, makeClient, makeDeployment, NOW } from '@/test/fixtures';
import { agentCertExpiring, connection, fileRows, headerConnectionLabel, shortHash } from './clientStatus';

describe('connection', () => {
  it.each([
    [makeClient({ status: 'revoked', connected: true }), 'revoked'],
    [makeClient({ connected: true }), 'online'],
    [makeClient({ connected: false, online: false, lastSeen: iso(-1) }), 'offline'],
    [makeClient({ status: 'pending', connected: false, online: false, lastSeen: null }), 'never'],
    [makeClient({ status: 'active', connected: false, online: false, lastSeen: null }), 'never'],
    // A pull-only agent seen 30 s ago: the server says online without a socket.
    [makeClient({ connected: false, online: true, lastSeen: new Date(NOW - 30_000).toISOString() }), 'online'],
  ])('%#', (c, want) => expect(connection(c)).toBe(want));

  it('labels the header Connected or Online (pull)', () => {
    expect(headerConnectionLabel(makeClient())).toBe('Connected');
    expect(headerConnectionLabel(makeClient({ connected: false, online: true }))).toBe('Online (pull)');
  });

  it('labels the header with the offline time', () => {
    expect(headerConnectionLabel(makeClient({ connected: false, online: false, lastSeen: '2026-09-24T09:05:00Z' }))).toMatch(/^Offline since /);
    expect(headerConnectionLabel(makeClient({ status: 'pending', connected: false, online: false, lastSeen: null }))).toBe('Never connected');
  });
});

it('flags an agent certificate under 14 days on an active client only', () => {
  expect(agentCertExpiring(makeClient({ agentCertNotAfter: iso(13) }), NOW)).toBe(true);
  expect(agentCertExpiring(makeClient({ agentCertNotAfter: iso(15) }), NOW)).toBe(false);
  expect(agentCertExpiring(makeClient({ status: 'revoked', agentCertNotAfter: iso(1) }), NOW)).toBe(false);
  expect(agentCertExpiring(makeClient({ agentCertNotAfter: null }), NOW)).toBe(false);
});

describe('fileRows', () => {
  const a = 'aa'.repeat(32);
  const b = 'bb'.repeat(32);
  it('marks each expected file ok, changed or missing, then lists unexpected ones', () => {
    const rows = fileRows(
      makeDeployment({
        expected: [{ path: '/x.pem', sha256: a }, { path: '/y.pem', sha256: a }, { path: '/z.pem', sha256: a }],
        installed: [{ path: '/x.pem', sha256: a }, { path: '/y.pem', sha256: b }, { path: '/z.pem', sha256: '' }, { path: '/w.pem', sha256: b }],
      }),
    );
    expect(rows.map((r) => [r.path, r.match])).toEqual([
      ['/x.pem', 'ok'], ['/y.pem', 'changed'], ['/z.pem', 'missing'], ['/w.pem', 'unexpected'],
    ]);
  });
  it('shortens digests', () => {
    expect(shortHash(a)).toBe('aaaaaaaaaaaa…');
    expect(shortHash(null)).toBe('–');
  });
});
