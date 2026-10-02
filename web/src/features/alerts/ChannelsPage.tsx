import { useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { createColumnHelper } from '@tanstack/react-table';
import { Globe, Plus } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { channelsQuery, updateChannel } from '@/api/queries/channels';
import type { Channel, Me, Org, Severity } from '@/api/types';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { canWriteChannel, toChannelInput, TYPE_META } from '@/lib/channels';
import { KIND_LABEL, SEVERITY_META } from '@/lib/events';
import { help } from '@/lib/help';
import { useMe, useOrg } from '@/lib/org';
import { can, isGlobalAdmin } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { ChannelSheet } from './ChannelSheet';
import { DeliveryChip } from './DeliveryChip';

const col = createColumnHelper<Channel>();
const CHANNEL_LIMIT = 50;
// UI conventions: the severity chip that follows the kind chips, only shown
// above info (Events column, Deviations "event severity chips").
const MIN_SEVERITY_LABEL: Partial<Record<Severity, string>> = { warning: 'Warning+', critical: 'Critical' };
const chipCls = 'inline-flex h-6 items-center whitespace-nowrap rounded-sm border border-border bg-subtle px-1.5 text-xs';

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

function EventsCell({ channel }: { channel: Channel }) {
  const shown = channel.events.slice(0, 3);
  const rest = channel.events.slice(3);
  return (
    <div className="flex flex-wrap items-center gap-1">
      {channel.events.length === 0 ? (
        <span className={`${chipCls} text-ink-muted`}>All events</span>
      ) : (
        <>
          {shown.map((k) => (
            <span key={k} className={chipCls}>
              {KIND_LABEL[k]}
            </span>
          ))}
          {rest.length > 0 && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span tabIndex={0} className={`${chipCls} cursor-default`}>
                  +{rest.length}
                </span>
              </TooltipTrigger>
              <TooltipContent>{rest.map((k) => KIND_LABEL[k]).join(', ')}</TooltipContent>
            </Tooltip>
          )}
        </>
      )}
      {channel.minSeverity !== 'info' && (
        <ToneChip tone={SEVERITY_META[channel.minSeverity].tone} icon={SEVERITY_META[channel.minSeverity].icon} label={MIN_SEVERITY_LABEL[channel.minSeverity]!} />
      )}
    </div>
  );
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
      meta: { className: 'w-48' },
      cell: ({ row }) => {
        const c = row.original;
        const owner = ownerOrgName(me, c, org.id);
        return (
          <div className="grid min-w-0 gap-0.5">
            <span className="flex items-center gap-1.5">
              <span className="truncate font-semibold">{c.name}</span>
              {c.allOrgs && <ToneChip tone="neutral" icon={Globe} label="All orgs" help="channel.allOrgs" />}
            </span>
            {owner && <span className="truncate text-xs text-ink-muted">{owner}</span>}
          </div>
        );
      },
    }),
    col.accessor('type', {
      header: 'Type',
      meta: { className: 'w-40' },
      cell: ({ getValue }) => {
        const m = TYPE_META[getValue()];
        return (
          <Tooltip>
            <TooltipTrigger asChild>
              <ToneChip tone="neutral" icon={m.icon} label={m.label} className="max-w-full min-w-0" truncate tabIndex={0} />
            </TooltipTrigger>
            <TooltipContent>{m.label}</TooltipContent>
          </Tooltip>
        );
      },
    }),
    col.accessor('summary', {
      header: 'Destination',
      meta: { className: 'w-48' },
      cell: ({ getValue }) => (
        <span title={getValue()} className="block truncate font-mono text-xs">
          {getValue()}
        </span>
      ),
    }),
    col.display({ id: 'events', header: 'Events', meta: { className: 'w-56' }, cell: ({ row }) => <EventsCell channel={row.original} /> }),
    col.display({
      id: 'enabled',
      header: 'Enabled',
      meta: { className: 'w-20' },
      cell: ({ row }) => <EnabledSwitch channel={row.original} routeOrgId={org.id} />,
    }),
    col.display({
      id: 'lastDelivery',
      header: () => (
        <span className="inline-flex items-center gap-1">
          Last delivery
          <HelpTip id="channel.lastDelivery" />
        </span>
      ),
      meta: { className: 'w-40' },
      cell: ({ row }) => <LastDeliveryCell channel={row.original} />,
    }),
  ];
}

function ChannelCard({ channel, org, me, onOpen }: { channel: Channel; org: Org; me: Me; onOpen: () => void }) {
  const m = TYPE_META[channel.type];
  const owner = ownerOrgName(me, channel, org.id);
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        // A bubbled Enter/Space from the nested Enabled switch must reach
        // its own default toggle action, not open the sheet on top of it
        // (batch 1 review) — only the card's own keydown (focused directly,
        // e.g. via Tab) opens it.
        if (e.target !== e.currentTarget) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen();
        }
      }}
      className="grid cursor-pointer gap-2 rounded-md border border-border bg-panel p-3 hover:bg-subtle"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-semibold">{channel.name}</span>
        <EnabledSwitch channel={channel} routeOrgId={org.id} />
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <ToneChip tone="neutral" icon={m.icon} label={m.label} />
        {channel.allOrgs && <ToneChip tone="neutral" icon={Globe} label="All orgs" />}
        {owner && <span className="text-xs text-ink-muted">{owner}</span>}
      </div>
      <span title={channel.summary} className="truncate font-mono text-xs text-ink-muted">
        {channel.summary}
      </span>
      <EventsCell channel={channel} />
      <LastDeliveryCell channel={channel} />
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
  const openSheet = (id: string | undefined) => void navigate({ search: (prev) => ({ ...prev, edit: id }), replace: id === undefined });
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
    <div className="grid gap-4">
      {q.isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : q.isError ? (
        <ErrorState message={`Couldn't load channels. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : channels.length === 0 ? (
        <EmptyState message="No channels yet.">{add}</EmptyState>
      ) : (
        <>
          <div className="flex justify-end">{add}</div>
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
  );
}
