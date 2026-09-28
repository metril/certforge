import { describe, expect, it } from 'vitest';
import type { DnsCredential, VerificationRule } from '@/api/types';
import { makeClient } from '@/test/fixtures';
import { cleanWebroot, clientOptions, METHOD_LABEL, ruleTarget, ruleUsable, webrootError, withMethod, withVia } from './rules';

describe('METHOD_LABEL', () => {
  it('labels every method', () => {
    expect(METHOD_LABEL).toEqual({ 'dns-01': 'DNS', 'manual-dns': 'Manual DNS', 'http-01': 'HTTP', 'tls-alpn-01': 'TLS-ALPN' });
  });
});

describe('withMethod', () => {
  const dns: VerificationRule = {
    match: 'example.com',
    method: 'dns-01',
    dnsCredentialId: 'd-1',
    propagationSeconds: 90,
    resolvers: ['1.1.1.1:53'],
    cnameAliasZone: 'acme.net',
  };

  it('dns-01 keeps its DNS fields', () => {
    expect(withMethod(dns, 'dns-01')).toEqual(dns);
  });

  it('manual-dns keeps only match and method', () => {
    expect(withMethod(dns, 'manual-dns')).toEqual({ match: 'example.com', method: 'manual-dns' });
  });

  it('http-01 defaults via to server and drops the DNS fields', () => {
    expect(withMethod(dns, 'http-01')).toEqual({ match: 'example.com', method: 'http-01', via: 'server' });
  });

  it('tls-alpn-01 has no clientId by default', () => {
    expect(withMethod(dns, 'tls-alpn-01')).toEqual({ match: 'example.com', method: 'tls-alpn-01' });
  });

  it('tls-alpn-01 keeps clientId coming from http-01 via agent', () => {
    const agent: VerificationRule = { match: 'example.com', method: 'http-01', via: 'agent', clientId: 'c-1' };
    expect(withMethod(agent, 'tls-alpn-01')).toEqual({ match: 'example.com', method: 'tls-alpn-01', clientId: 'c-1' });
  });

  it('tls-alpn-01 does not carry a clientId over from http-01 via server', () => {
    const server: VerificationRule = { match: 'example.com', method: 'http-01', via: 'server', clientId: 'c-1' };
    expect(withMethod(server, 'tls-alpn-01')).toEqual({ match: 'example.com', method: 'tls-alpn-01' });
  });
});

describe('withVia', () => {
  it('server clears client and webroot', () => {
    const rule: VerificationRule = { match: 'example.com', method: 'http-01', via: 'agent', clientId: 'c-1', webroot: '/srv/acme' };
    expect(withVia(rule, 'server')).toEqual({ match: 'example.com', method: 'http-01', via: 'server' });
  });

  it('agent keeps whatever clientId is already set', () => {
    const rule: VerificationRule = { match: 'example.com', method: 'http-01', via: 'server' };
    expect(withVia(rule, 'agent')).toEqual({ match: 'example.com', method: 'http-01', via: 'agent' });
  });
});

const clients = [
  makeClient({ id: 'c-1', name: 'web-1', status: 'active', capabilities: ['http-01'] }),
  makeClient({ id: 'c-2', name: 'web-2', status: 'active', capabilities: ['tls-alpn-01'] }),
  makeClient({ id: 'c-3', name: 'web-3', status: 'pending', capabilities: ['http-01', 'tls-alpn-01'] }),
];

describe('ruleUsable', () => {
  it('dns-01 needs a credential', () => {
    expect(ruleUsable({ match: '*', method: 'dns-01' }, [])).toBe(false);
    expect(ruleUsable({ match: '*', method: 'dns-01', dnsCredentialId: 'd-1' }, [])).toBe(true);
  });
  it('manual-dns is always usable', () => {
    expect(ruleUsable({ match: '*', method: 'manual-dns' }, [])).toBe(true);
  });
  it('http-01 via server is always usable; via agent needs a client that reports the capability', () => {
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'server' }, [])).toBe(true);
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'agent' }, clients)).toBe(false);
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'agent', clientId: 'c-1' }, clients)).toBe(true);
  });
  it('tls-alpn-01 needs a client that reports the capability', () => {
    expect(ruleUsable({ match: '*', method: 'tls-alpn-01' }, clients)).toBe(false);
    expect(ruleUsable({ match: '*', method: 'tls-alpn-01', clientId: 'c-2' }, clients)).toBe(true);
  });
});

// Review fix round 2 (controller ruling): ruleUsable's `clients` is no
// longer an opt-in fallback — every real caller (coverage.ts, threaded
// through to every CoveragePanel/wizard caller) always has the list, so a
// client that lost the capability (or was only ever picked because a
// webroot was set) is caught the same way everywhere, not just where a
// caller happened to pass clients in.
describe('ruleUsable catches a client that no longer qualifies (review fix round 2)', () => {
  const noCap = [makeClient({ id: 'c-1', name: 'web-1', status: 'active', capabilities: [] })];
  const capable = [makeClient({ id: 'c-1', name: 'web-1', status: 'active', capabilities: ['http-01'] })];

  it('http-01 via agent: a client with no capability and no webroot is not usable', () => {
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'agent', clientId: 'c-1' }, noCap)).toBe(false);
  });
  it('http-01 via agent: the same client becomes usable once a webroot is set', () => {
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'agent', clientId: 'c-1', webroot: '/srv/acme' }, noCap)).toBe(true);
  });
  it('http-01 via agent: a capable client is usable either way', () => {
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'agent', clientId: 'c-1' }, capable)).toBe(true);
  });
  it('tls-alpn-01: a client with no capability is not usable', () => {
    expect(ruleUsable({ match: '*', method: 'tls-alpn-01', clientId: 'c-1' }, noCap)).toBe(false);
  });
});

describe('clientOptions', () => {
  it('filters by capability and active status', () => {
    expect(clientOptions(clients, 'http-01').map((c) => c.id)).toEqual(['c-1']);
    expect(clientOptions(clients, 'tls-alpn-01').map((c) => c.id)).toEqual(['c-2']);
  });

  it('http-01 with a non-empty webroot lists every active client, regardless of capability', () => {
    expect(clientOptions(clients, 'http-01', '/srv/acme').map((c) => c.id)).toEqual(['c-1', 'c-2']);
  });

  it('an empty or blank webroot still filters by capability', () => {
    expect(clientOptions(clients, 'http-01', '').map((c) => c.id)).toEqual(['c-1']);
    expect(clientOptions(clients, 'http-01', '   ').map((c) => c.id)).toEqual(['c-1']);
  });
});

describe('ruleTarget', () => {
  const creds: DnsCredential[] = [{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }];
  it('manual-dns', () => expect(ruleTarget({ match: '*', method: 'manual-dns' }, creds, clients)).toBe('manual'));
  it('dns-01 with a credential', () => expect(ruleTarget({ match: '*', method: 'dns-01', dnsCredentialId: 'd-1' }, creds, clients)).toBe('Cloudflare prod'));
  it('dns-01 without a credential', () => expect(ruleTarget({ match: '*', method: 'dns-01' }, creds, clients)).toBe('no credential'));
  it('http-01 via server', () => expect(ruleTarget({ match: '*', method: 'http-01', via: 'server' }, creds, clients)).toBe('server'));
  it('http-01 via agent with a client', () => expect(ruleTarget({ match: '*', method: 'http-01', via: 'agent', clientId: 'c-1' }, creds, clients)).toBe('web-1'));
  it('http-01 via agent without a client', () => expect(ruleTarget({ match: '*', method: 'http-01', via: 'agent' }, creds, clients)).toBe('no client'));
  it('tls-alpn-01 with a client', () => expect(ruleTarget({ match: '*', method: 'tls-alpn-01', clientId: 'c-2' }, creds, clients)).toBe('web-2'));
  it('tls-alpn-01 without a client', () => expect(ruleTarget({ match: '*', method: 'tls-alpn-01' }, creds, clients)).toBe('no client'));
});

// Review fix round 1 (Minor): webroot names a directory, not a file, so a
// trailing slash (the natural way to type one) must not be rejected with
// pathError's file-specific "Name a file, not a directory." message.
it('webrootError tolerates a trailing slash', () => {
  expect(webrootError('/srv/acme')).toBeNull();
  expect(webrootError('/srv/acme/')).toBeNull();
  expect(webrootError('relative')).not.toBeNull();
  expect(webrootError('/')).not.toBeNull();
});

// Fix wave (Important): a trailing slash passed webrootError's own browser
// check but 422'd against the server's cleanWebroot, because the editor
// stored the value exactly as typed instead of the same slash-stripped form
// it validated. cleanWebroot is what the editor now applies on change.
describe('cleanWebroot', () => {
  it('strips exactly one trailing slash', () => {
    expect(cleanWebroot('/srv/acme/')).toBe('/srv/acme');
    expect(cleanWebroot('/srv/acme')).toBe('/srv/acme');
  });
  it('leaves a lone "/" alone, so it stays invalid rather than becoming empty', () => {
    expect(cleanWebroot('/')).toBe('/');
  });
});

