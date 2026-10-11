import { describe, expect, it } from 'vitest';
import { edgeRelation, flowStatusLabel } from './flowLabels';

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
