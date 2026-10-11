import { describe, expect, it } from 'vitest';
import { edgeRelation, flowStatusLabel, nodeMeta } from './flowLabels';

describe('flowStatusLabel', () => {
  it('words issuers by use', () => {
    expect(flowStatusLabel('ca', 'valid')).toBe('In use');
    expect(flowStatusLabel('account', 'idle')).toBe('Unused');
    expect(flowStatusLabel('dnsCredential', 'valid')).toBe('In use');
    expect(flowStatusLabel('ca', 'expiring')).toBe('Expiring');
    expect(flowStatusLabel('account', 'failed')).toBe('Failed');
  });
  it('calls an issuer no certificate resolves to unused', () => {
    expect(flowStatusLabel('ca', 'idle', 'Not used by any certificate')).toBe('Unused');
  });
  it('words channels by delivery', () => {
    expect(flowStatusLabel('channel', 'valid')).toBe('Delivering');
    expect(flowStatusLabel('channel', 'failed')).toBe('Failing');
    expect(flowStatusLabel('channel', 'pending', 'Delivery pending')).toBe('Delivery pending');
    expect(flowStatusLabel('channel', 'idle', 'Disabled')).toBe('Disabled');
    expect(flowStatusLabel('channel', 'idle', 'No deliveries yet')).toBe('No deliveries yet');
    expect(flowStatusLabel('channel', 'idle')).toBe('No deliveries yet');
  });
  it('keeps generic words elsewhere', () => {
    expect(flowStatusLabel('certificate', 'valid')).toBe('Healthy');
    expect(flowStatusLabel('layout', 'idle')).toBe('Idle');
    expect(flowStatusLabel('client', 'pending')).toBe('Pending');
  });
});

describe('edgeRelation', () => {
  it('names the link by lane pair, in either order', () => {
    expect(edgeRelation('ca', 'certificate')).toBe('issues');
    expect(edgeRelation('certificate', 'account')).toBe('issues');
    expect(edgeRelation('certificate', 'layout')).toBe('delivered by');
    expect(edgeRelation('layout', 'client')).toBe('grant');
    expect(edgeRelation('client', 'certificate')).toBe('grant');
    expect(edgeRelation('certificate', 'channel')).toBe('alerts');
    expect(edgeRelation('ca', 'client')).toBe('link');
  });
});

describe('nodeMeta', () => {
  const now = Date.parse('2026-01-01T00:00:00Z');
  const n = (kind: string, extra = {}) => ({ id: `${kind}:x`, kind, name: 'x', status: 'valid', href: '/', ...extra }) as never;
  it('reads per kind and is empty when there is nothing to say', () => {
    expect(nodeMeta(n('certificate', { summary: { expiresAt: '2026-01-13T00:00:00Z' } }), { up: 1, down: 2 }, now)).toBe('in 12 d');
    expect(nodeMeta(n('certificate', { summary: { versionSerial: 'ab12' } }), undefined, now)).toBe('ab12');
    expect(nodeMeta(n('client', { summary: { lastDeployedAt: '2025-12-31T22:00:00Z' } }), undefined, now)).toBe('deployed 2 h ago');
    expect(nodeMeta(n('target', { summary: { clientIds: ['a', 'b', 'c'] } }), undefined, now)).toBe('3 hosts');
    expect(nodeMeta(n('ca'), { up: 0, down: 4 }, now)).toBe('4 certificates');
    expect(nodeMeta(n('channel', { coversCertificates: true }), undefined, now)).toBe('Covers this org');
    expect(nodeMeta(n('client'), undefined, now)).toBe('');
  });
});
