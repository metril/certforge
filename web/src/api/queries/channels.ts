import { queryOptions } from '@tanstack/react-query';
import { api, call } from '../client';
import type { Channel, ChannelInput, DeliveryResult } from '../types';

export const channelsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['channels', orgId],
    queryFn: () => call(api.GET('/orgs/{orgId}/channels', { params: { path: { orgId } } })),
  });

// Direct calls, not useMutation (global constraints, "Secrets" — a channel's
// config can carry a fresh secret, which must never sit in the mutation
// cache). Every path uses the channel's own org, never the route org, since
// a global admin can write another org's allOrgs channel.
export function createChannel(orgId: string, body: ChannelInput): Promise<Channel> {
  return call(api.POST('/orgs/{orgId}/channels', { params: { path: { orgId } }, body }));
}

export function updateChannel(channel: Pick<Channel, 'orgId' | 'id'>, body: ChannelInput): Promise<Channel> {
  return call(api.PATCH('/orgs/{orgId}/channels/{id}', { params: { path: { orgId: channel.orgId, id: channel.id } }, body }));
}

export function deleteChannel(channel: Pick<Channel, 'orgId' | 'id'>): Promise<void> {
  return call(api.DELETE('/orgs/{orgId}/channels/{id}', { params: { path: { orgId: channel.orgId, id: channel.id } } }));
}

export function testChannel(channel: Pick<Channel, 'orgId' | 'id'>): Promise<DeliveryResult> {
  return call(api.POST('/orgs/{orgId}/channels/{id}/test', { params: { path: { orgId: channel.orgId, id: channel.id } } }));
}
