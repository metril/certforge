import { describe, expect, it } from 'vitest';
import type { DnsCredential, VerificationRule } from '@/api/types';
import { makeClient } from '@/test/fixtures';
import { clientOptions, METHOD_LABEL, ruleTarget, ruleUsable, webrootError, withMethod, withVia } from './rules';

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

describe('ruleUsable', () => {
  it('dns-01 needs a credential', () => {
    expect(ruleUsable({ match: '*', method: 'dns-01' })).toBe(false);
    expect(ruleUsable({ match: '*', method: 'dns-01', dnsCredentialId: 'd-1' })).toBe(true);
  });
  it('manual-dns is always usable', () => {
    expect(ruleUsable({ match: '*', method: 'manual-dns' })).toBe(true);
  });
  it('http-01 via server is always usable; via agent needs a client', () => {
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'server' })).toBe(true);
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'agent' })).toBe(false);
    expect(ruleUsable({ match: '*', method: 'http-01', via: 'agent', clientId: 'c-1' })).toBe(true);
  });
  it('tls-alpn-01 needs a client', () => {
    expect(ruleUsable({ match: '*', method: 'tls-alpn-01' })).toBe(false);
    expect(ruleUsable({ match: '*', method: 'tls-alpn-01', clientId: 'c-1' })).toBe(true);
  });
});

const clients = [
  makeClient({ id: 'c-1', name: 'web-1', status: 'active', capabilities: ['http-01'] }),
  makeClient({ id: 'c-2', name: 'web-2', status: 'active', capabilities: ['tls-alpn-01'] }),
  makeClient({ id: 'c-3', name: 'web-3', status: 'pending', capabilities: ['http-01', 'tls-alpn-01'] }),
];

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

it('webrootError is pathError', () => {
  expect(webrootError('/srv/acme')).toBeNull();
  expect(webrootError('relative')).not.toBeNull();
});
