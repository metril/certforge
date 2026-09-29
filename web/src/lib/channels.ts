import { BellRing, Mail, MessageSquare, House, Webhook, type LucideIcon } from 'lucide-react';
import { UNCHANGED, type Channel, type ChannelInput, type ChannelType, type Me } from '@/api/types';
import { can, isGlobalAdmin } from './permissions';

/** Labels mirror each notifier's `name` from GET /meta/schemas (UI conventions). */
export const TYPE_META: Record<ChannelType, { label: string; icon: LucideIcon }> = {
  webhook: { label: 'Webhook', icon: Webhook },
  smtp: { label: 'Email', icon: Mail },
  discord: { label: 'Discord', icon: MessageSquare },
  ntfy: { label: 'ntfy', icon: BellRing },
  homeassistant: { label: 'Home Assistant', icon: House },
};

/** The channel's own public config plus the stored-secret sentinel for each
 * name in storedSecrets, with patch applied on top (global constraints,
 * "Secrets" — a stored secret round-trips as __unchanged__, never its
 * value). */
export function toChannelInput(channel: Channel, patch: Partial<ChannelInput> = {}): ChannelInput {
  const config: Record<string, unknown> = { ...channel.config };
  for (const key of channel.storedSecrets) config[key] = UNCHANGED;
  return {
    name: channel.name,
    type: channel.type,
    config,
    events: channel.events,
    minSeverity: channel.minSeverity,
    allOrgs: channel.allOrgs,
    enabled: channel.enabled,
    ...patch,
  };
}

/** alerts:write on the channel's own org, and a global admin when the
 * channel is allOrgs (Shared contracts, UI conventions "Other org's channel"). */
export function canWriteChannel(me: Pick<Me, 'bindings'>, channel: Pick<Channel, 'orgId' | 'allOrgs'>): boolean {
  if (!can(me, 'alerts:write', channel.orgId)) return false;
  return !channel.allOrgs || isGlobalAdmin(me);
}
