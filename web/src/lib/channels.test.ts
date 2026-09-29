import { describe, expect, it } from 'vitest';
import { org, org2, meWith } from '@/test/fixtures';
import { UNCHANGED } from '@/api/types';
import { canWriteChannel, toChannelInput, TYPE_META } from './channels';

const channel = {
  id: 'ch-1', orgId: org.id, name: 'ops', type: 'webhook' as const, summary: 'hooks.example.com',
  config: { headers: {} }, storedSecrets: ['url', 'signingSecret'], events: [], minSeverity: 'info' as const,
  allOrgs: false, enabled: true, lastDelivery: null, createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z',
};

describe('toChannelInput', () => {
  it('sends stored secrets as sentinel', () => {
    const input = toChannelInput(channel);
    expect(input.config.url).toBe(UNCHANGED);
    expect(input.config.signingSecret).toBe(UNCHANGED);
    expect(input.config.headers).toEqual({});
    expect(input.name).toBe('ops');
    expect(input.type).toBe('webhook');
  });

  it('patch overrides the base', () => {
    const input = toChannelInput(channel, { name: 'renamed', enabled: false });
    expect(input.name).toBe('renamed');
    expect(input.enabled).toBe(false);
  });
});

describe('canWriteChannel', () => {
  it('needs global admin for allOrgs', () => {
    const orgAdmin = meWith([{ role: 'org-admin', orgId: org.id }]);
    const globalAdmin = meWith([{ role: 'admin', orgId: null }]);
    const allOrgsChannel = { ...channel, allOrgs: true };
    expect(canWriteChannel(orgAdmin, allOrgsChannel)).toBe(false);
    expect(canWriteChannel(globalAdmin, allOrgsChannel)).toBe(true);
    expect(canWriteChannel(orgAdmin, channel)).toBe(true);
  });

  it('needs alerts:write in the channel org', () => {
    const viewer = meWith([{ role: 'viewer', orgId: org.id }]);
    const otherOrg = meWith([{ role: 'operator', orgId: org2.id }], [org, org2]);
    expect(canWriteChannel(viewer, channel)).toBe(false);
    expect(canWriteChannel(otherOrg, channel)).toBe(false);
  });
});

it('has type meta for every channel type', () => {
  for (const t of ['webhook', 'smtp', 'discord', 'ntfy', 'homeassistant'] as const) {
    expect(TYPE_META[t].label).toBeTruthy();
    expect(TYPE_META[t].icon).toBeTruthy();
  }
});
