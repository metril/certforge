import { useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { createColumnHelper } from '@tanstack/react-table';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { channelsQuery, updateChannel } from '@/api/queries/channels';
import type { Channel, Me, Org, Severity } from '@/api/types';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { PermissionTip } from '@/components/PermissionTip';
import { PrimaryCell } from '@/components/PrimaryCell';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Switch } from '@/components/ui/switch';
import { canWriteChannel, toChannelInput, TYPE_META } from '@/lib/channels';
import { KIND_LABEL } from '@/lib/events';
import { help } from '@/lib/help';
import { failedWithoutData } from '@/lib/queryState';
import { useMe, useOrg } from '@/lib/org';
import { can, isGlobalAdmin } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { AlertsHeader } from './AlertsLayout';
import { ChannelSheet } from './ChannelSheet';
import { DeliveryChip } from './DeliveryChip';

const col = createColumnHelper<Channel>();
const CHANNEL_LIMIT = 50;
// UI conventions: the severity chip that follows the kind chips, only shown
// above info (Events column, Deviations "event severity chips").
const MIN_SEVERITY_LABEL: Partial<Record<Severity, string>> = {
  warning: 'Warning+',
  critical: 'Critical',
};

function ownerOrgName(me: Pick<Me, 'orgs'>, channel: Channel, routeOrgId: string): string | undefined {
  return channel.orgId !== routeOrgId ? me.orgs.find((o) => o.id === channel.orgId)?.name : undefined;
}

/** The channel's own writer's switch: a full ChannelInput (public config
 * plus stored-secret sentinels) with only `enabled` patched, never a
 * partial body (global constraints "Full-input PATCH"). Direct call, not
 * useMutation — a channel's config can carry a fresh secret that must never
 * sit in the mutation cache (global constraints "Secrets"). */
function EnabledSwitch({ channel, routeOrgId }: { channel: Channel; routeOrgId: string }) {
  const me = useMe();
  const qc = useQueryClient();
  const [pending, setPending] = useState(false);
  const allowed = canWriteChannel(me, channel);
  const reason = !can(me, 'alerts:write', channel.orgId) ? undefined : channel.allOrgs && !isGlobalAdmin(me) ? 'Needs a global admin' : undefined;
  return (
    <PermissionTip allowed={allowed} action="alerts:write" reason={reason}>
      <Switch
        checked={channel.enabled}
        disabled={!allowed || pending}
        aria-label={`Enabled ${channel.name}`}
        onClick={(e) => e.stopPropagation()}
        onCheckedChange={(on) => {
          setPending(true);
          updateChannel(channel, toChannelInput(channel, { enabled: on }))
            .then(() => qc.invalidateQueries({ queryKey: ['channels', routeOrgId] }))
            .catch((e: unknown) => toast.error(errorMessage(e)))
            .finally(() => setPending(false));
        }}
      />
    </PermissionTip>
  );
}

/** Plain-text summary of the kinds a channel receives (no chips). */
function eventsText(channel: Channel): string {
  const kinds = channel.events.length === 0 ? 'All events' : channel.events.map((k) => KIND_LABEL[k]).join(', ');
  const floor = MIN_SEVERITY_LABEL[channel.minSeverity];
  return floor ? `${kinds} (${floor})` : kinds;
}

/** Muted second line shared by the table row and the mobile card. */
function channelMeta(me: Me, org: Org, c: Channel): string[] {
  return [TYPE_META[c.type].label, c.summary, ownerOrgName(me, c, org.id) ?? '', c.allOrgs ? 'All orgs' : '', eventsText(c)].filter(Boolean);
}

function LastDeliveryCell({ channel }: { channel: Channel }) {
  const d = channel.lastDelivery;
  if (!d) return <span className="text-xs text-ink-muted">Never</span>;
  return (
    <span className="inline-flex items-center gap-1.5">
      <DeliveryChip kind="channel" status={d.status} at={d.at} error={d.error} />
      <span className="text-xs text-ink-muted">{relTime(d.at)}</span>
    </span>
  );
}

function channelColumns(me: Me, org: Org) {
  return [
    col.accessor('name', {
      header: 'Name',
      cell: ({ row }) => <PrimaryCell primary={row.original.name} meta={channelMeta(me, org, row.original)} />,
    }),
    col.display({
      id: 'lastDelivery',
      header: 'Last delivery',
      meta: { className: 'w-44' },
      cell: ({ row }) => <LastDeliveryCell channel={row.original} />,
    }),
    col.display({
      id: 'enabled',
      header: 'Enabled',
      meta: { className: 'w-24' },
      cell: ({ row }) => <EnabledSwitch channel={row.original} routeOrgId={org.id} />,
    }),
  ];
}

function ChannelCard({ channel, org, me, onOpen }: { channel: Channel; org: Org; me: Me; onOpen: () => void }) {
  return (
    <div
      className="relative grid gap-2 rounded-md border border-border bg-panel p-3 hover:bg-subtle"
    >
      <div className="flex items-center justify-between gap-2">
        <button type="button" onClick={onOpen} className="truncate text-left font-semibold after:absolute after:inset-0 after:content-[''] focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-ring/50 focus-visible:after:rounded-md">
          {channel.name}
        </button>
        <span className="relative z-10">
          <EnabledSwitch channel={channel} routeOrgId={org.id} />
        </span>
      </div>
      <span className="text-xs text-ink-muted">{channelMeta(me, org, channel).join(' · ')}</span>
      {/* z-10: the title's stretched overlay must not cover the chip's tooltip trigger. */}
      <span className="relative z-10 w-fit">
        <LastDeliveryCell channel={channel} />
      </span>
    </div>
  );
}

export function ChannelsPage() {
  const org = useOrg();
  const me = useMe();
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const { edit } = useSearch({ from: '/_app/o/$org/alerts/channels' });
  const navigate = useNavigate({ from: '/o/$org/alerts/channels' });
  const q = useQuery(channelsQuery(org.id));
  const channels = q.data ?? [];
  const canWrite = can(me, 'alerts:write', org.id);
  // The 50-cap is per org: `channels` also carries other orgs' allOrgs rows
  // a global admin sees here, which must not count against this org's own
  // limit (batch 1 review).
  const atLimit = channels.filter((c) => c.orgId === org.id).length >= CHANNEL_LIMIT;
  const addAllowed = canWrite && !atLimit;
  const openSheet = (id: string | undefined) =>
    void navigate({
      search: (prev) => ({ ...prev, edit: id }),
      replace: id === undefined,
    });
  const columns = useMemo(() => channelColumns(me, org), [me, org]);
  const editing = channels.find((c) => c.id === edit);
  const editNotFound = !q.isPending && !q.isError && !!edit && edit !== 'new' && !editing;

  const add = (
    <PermissionTip allowed={addAllowed} action="alerts:write" reason={!canWrite ? undefined : atLimit ? help['channel.limit'].text : undefined}>
      <Button disabled={!addAllowed} onClick={() => openSheet('new')}>
        <Plus className="size-4" aria-hidden />
        Add channel
      </Button>
    </PermissionTip>
  );

  return (
    <>
      <AlertsHeader help="alerts.channels" actions={q.isPending || failedWithoutData(q) || channels.length === 0 ? undefined : add} />
      <div className="grid gap-4">
        {q.isPending ? (
          <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
        ) : failedWithoutData(q) ? (
          <ErrorState message={`Couldn't load channels. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
        ) : channels.length === 0 ? (
          <EmptyState message="No channels yet.">{add}</EmptyState>
        ) : (
          <>
            {isMdUp ? (
              <DataTable ariaLabel="Channels" data={channels} columns={columns} getRowId={(c) => c.id} onRowClick={(id) => openSheet(id)} />
            ) : (
              <div className="grid gap-2">
                {channels.map((c) => (
                  <ChannelCard key={c.id} channel={c} org={org} me={me} onOpen={() => openSheet(c.id)} />
                ))}
              </div>
            )}
          </>
        )}
        {(edit === 'new' || editing) && (
          // Mount only once the channel is loaded so the sheet initialises from it.
          <ChannelSheet key={edit} orgId={org.id} open channel={editing} onOpenChange={(o) => !o && openSheet(undefined)} />
        )}
        {editNotFound && (
          <Sheet open onOpenChange={(o) => !o && openSheet(undefined)}>
            <SheetContent side="right" className="w-full sm:max-w-lg">
              <SheetHeader>
                <SheetTitle>Channel not found</SheetTitle>
                <SheetDescription>It may have been deleted.</SheetDescription>
              </SheetHeader>
              <div className="px-4">
                <Button onClick={() => openSheet(undefined)}>Back to channels</Button>
              </div>
            </SheetContent>
          </Sheet>
        )}
      </div>
    </>
  );
}
