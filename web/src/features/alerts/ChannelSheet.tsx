import { useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { ErrorSchema, RJSFSchema } from '@rjsf/utils';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { createChannel, deleteChannel, updateChannel } from '@/api/queries/channels';
import { metaSchemasQuery } from '@/api/queries/dns';
import { type Channel, type ChannelInput, type ChannelType, type EventKind, type Severity } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { FormSection } from '@/components/FormSection';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetClose } from '@/components/ui/sheet';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { fieldErrorFromMessage } from '@/forms/uiSchema';
import { canWriteChannel, TYPE_META } from '@/lib/channels';
import { SEVERITY_META } from '@/lib/events';
import type { HelpKey } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can, isGlobalAdmin } from '@/lib/permissions';
import { stripSecretDefaults, withStoredSentinels } from '@/lib/secretForm';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { ChannelTest } from './ChannelTest';
import { EventKindPicker } from './EventKindPicker';

const TYPE_ORDER: ChannelType[] = ['webhook', 'smtp', 'discord', 'ntfy', 'homeassistant'];
const SEVERITY_ORDER: Severity[] = ['info', 'warning', 'critical'];

// ntfy/HA re-entry rule (6a-facts, task-3-brief "Errors"): a 422 "re-enter
// the secret" on one of these two types names the one secret field whose
// __unchanged__ sentinel needs a fresh value because the channel's own
// non-secret host field (server/baseUrl) changed. Webhook's own re-entry
// case (url itself the secret that changed) isn't mapped here — the brief
// scopes this mapping to ntfy/HA only; anything else falls through to
// fieldErrorFromMessage/a toast.
const REENTRY_FIELD: Partial<Record<ChannelType, string>> = { ntfy: 'token', homeassistant: 'webhookId' };

type Draft = {
  name: string;
  type: ChannelType;
  /** One config draft per type, so switching the type segmented control
   * (new channel only — locked on edit) doesn't lose what was typed for a
   * type visited earlier. */
  configs: Record<ChannelType, Record<string, unknown>>;
  events: EventKind[];
  minSeverity: Severity;
  allOrgs: boolean;
  enabled: boolean;
};

function emptyConfigs(): Record<ChannelType, Record<string, unknown>> {
  return { webhook: {}, smtp: {}, discord: {}, ntfy: {}, homeassistant: {} };
}

function initialDraft(channel?: Channel): Draft {
  const configs = emptyConfigs();
  if (channel) configs[channel.type] = { ...(channel.config as Record<string, unknown>) };
  return {
    name: channel?.name ?? '',
    type: channel?.type ?? 'webhook',
    configs,
    events: channel?.events ?? [],
    minSeverity: channel?.minSeverity ?? 'info',
    allOrgs: channel?.allOrgs ?? false,
    enabled: channel?.enabled ?? true,
  };
}

/** The fields Send test's "saved config" check (dirty) cares about — every
 * type's config draft except the active one is irrelevant to what's saved.
 * `config` goes through `withStoredSentinels` (lib/secretForm.ts) before the
 * comparison, so a config with the stored-secret sentinel already applied
 * and one that hasn't gotten there yet (SecretInput fills it in only once
 * its own mount effect runs) compare identically. */
function snapshot(schema: RJSFSchema, storedSecrets: string[], d: Pick<Draft, 'name' | 'type' | 'events' | 'minSeverity' | 'allOrgs' | 'enabled'> & { config: Record<string, unknown> }): string {
  return JSON.stringify({
    name: d.name,
    type: d.type,
    config: withStoredSentinels(schema, d.config, storedSecrets),
    events: d.events,
    minSeverity: d.minSeverity,
    allOrgs: d.allOrgs,
    enabled: d.enabled,
  });
}

function toInput(d: Draft, schema: RJSFSchema, storedSecrets: string[]): ChannelInput {
  return {
    name: d.name,
    type: d.type,
    config: withStoredSentinels(schema, d.configs[d.type], storedSecrets),
    events: d.events,
    minSeverity: d.minSeverity,
    allOrgs: d.allOrgs,
    enabled: d.enabled,
  };
}

type Props = { orgId: string; open: boolean; channel?: Channel; onOpenChange: (open: boolean) => void };

export function ChannelSheet({ orgId, open, channel, onOpenChange }: Props) {
  const qc = useQueryClient();
  const me = useMe();
  const isSmUp = useMediaQuery('(min-width: 640px)');
  const { data: meta } = useQuery(metaSchemasQuery);
  const formRef = useRef<SchemaFormHandle>(null);
  const [draft, setDraft] = useState<Draft>(() => initialDraft(channel));
  const [submitted, setSubmitted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [configError, setConfigError] = useState<ErrorSchema | undefined>(undefined);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const initialDraftRef = useRef<Draft>(draft);

  // Stripped so RJSF shows a secret's schema default only as a placeholder,
  // never fills it into formData — otherwise withStoredSentinels never adds
  // the sentinel (the key is no longer undefined) and an untouched save
  // overwrites the stored value with the default (lib/secretForm.ts).
  const schema = useMemo(() => {
    const raw = (meta?.notifiers.find((n) => n.code === draft.type)?.schema as RJSFSchema | undefined) ?? { type: 'object', properties: {} };
    return stripSecretDefaults(raw);
  }, [meta, draft.type]);
  // Stored secrets only apply to the channel's own (locked, on edit) type.
  const storedSecrets = channel && channel.type === draft.type ? channel.storedSecrets : [];
  const nameOk = draft.name.trim() !== '';
  // Send test always uses the saved config (Review Focus, "Tests against
  // unsaved drafts") — a brand-new, unsaved channel has no saved config at
  // all, so it's always dirty regardless of the draft.
  const dirty = !channel || snapshot(schema, storedSecrets, { ...draft, config: draft.configs[draft.type] }) !== snapshot(schema, storedSecrets, { ...channel, config: channel.config as Record<string, unknown> });
  // Discard guard: an existing channel reuses the saved-config comparison; a
  // new one compares against its initial draft.
  const formDirty = channel ? dirty : snapshot(schema, [], { ...draft, config: draft.configs[draft.type] }) !== snapshot(schema, [], { ...initialDraftRef.current, config: initialDraftRef.current.configs[initialDraftRef.current.type] });
  // A channel targets its own org, never the route org (a global admin can
  // edit another org's allOrgs channel) — a new channel always belongs to
  // the current route org.
  const targetOrgId = channel?.orgId ?? orgId;
  const canWrite = canWriteChannel(me, { orgId: targetOrgId, allOrgs: draft.allOrgs });
  const writeReason = !can(me, 'alerts:write', targetOrgId) ? undefined : 'Needs a global admin';

  function setConfig(type: ChannelType, value: Record<string, unknown>) {
    setDraft((d) => ({ ...d, configs: { ...d.configs, [type]: value } }));
  }

  async function submit() {
    setSubmitted(true);
    setConfigError(undefined);
    const formOk = formRef.current?.validate() ?? true;
    if (!nameOk || !formOk) return;
    setSaving(true);
    try {
      const input = toInput(draft, schema, storedSecrets);
      if (channel) await updateChannel(channel, input);
      else await createChannel(orgId, input);
      await qc.invalidateQueries({ queryKey: ['channels', orgId] });
      onOpenChange(false);
    } catch (e) {
      const message = errorMessage(e);
      if (e instanceof ApiError && e.status === 422) {
        const reentryField = REENTRY_FIELD[draft.type];
        if (reentryField && /re-enter the secret/i.test(message)) {
          setConfigError({ [reentryField]: { __errors: [message] } } as ErrorSchema);
        } else {
          const mapped = fieldErrorFromMessage(schema, message);
          if (mapped) setConfigError(mapped);
          else toast.error(message);
        }
      } else {
        toast.error(message);
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet open={open} form dirty={formDirty} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{channel ? channel.name : 'New channel'}</SheetTitle>
          <SheetDescription className="sr-only">Notification channel settings</SheetDescription>
        </SheetHeader>
        <div className="px-4">
          <ChannelTest channel={channel} orgId={orgId} dirty={dirty} canWrite={canWrite} />
        </div>
        <form
          className="grid gap-5 px-4"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Field id="channel-name" label="Name" error={submitted && !nameOk ? 'Required' : null}>
            <Input id="channel-name" value={draft.name} onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))} placeholder="ops-webhook" />
          </Field>
          <Field id="channel-type" label="Type" help="channel.type">
            <span className="flex items-start gap-1.5">
              <SegmentedControl<ChannelType>
                id="channel-type"
                aria-label="Type"
                value={draft.type}
                onChange={(type) => setDraft((d) => ({ ...d, type }))}
                options={TYPE_ORDER.map((t) => {
                  const Icon = TYPE_META[t].icon;
                  return {
                    value: t,
                    label: isSmUp ? (
                      <span className="inline-flex items-center gap-1.5">
                        <Icon className="size-4" aria-hidden />
                        {TYPE_META[t].label}
                      </span>
                    ) : (
                      <>
                        <Icon className="size-4" aria-hidden />
                        <span className="sr-only">{TYPE_META[t].label}</span>
                      </>
                    ),
                    disabled: !!channel,
                    hint: !isSmUp ? TYPE_META[t].label : undefined,
                  };
                })}
              />
              <span className="flex h-9 shrink-0 items-center">
                <HelpTip id={`notifier.${draft.type}` as HelpKey} />
              </span>
            </span>
          </Field>
          <SchemaForm
            ref={formRef}
            schema={schema}
            value={draft.configs[draft.type]}
            onChange={(v) => setConfig(draft.type, v)}
            storedSecrets={storedSecrets}
            extraErrors={configError}
          />
          <EventKindPicker value={draft.events} onChange={(events) => setDraft((d) => ({ ...d, events }))} />
          <SwitchField
            id="channel-enabled"
            label="Enabled"
            help="channel.enabled"
            checked={draft.enabled}
            onCheckedChange={(enabled) => setDraft((d) => ({ ...d, enabled }))}
          />
          <FormSection title="Advanced" collapsible count={(draft.minSeverity !== 'info' ? 1 : 0) + (draft.allOrgs ? 1 : 0)}>
            <Field id="channel-severity" label="Minimum severity" help="channel.minSeverity">
              <SegmentedControl<Severity>
                id="channel-severity"
                aria-label="Minimum severity"
                value={draft.minSeverity}
                onChange={(minSeverity) => setDraft((d) => ({ ...d, minSeverity }))}
                options={SEVERITY_ORDER.map((s) => ({ value: s, label: SEVERITY_META[s].label }))}
              />
            </Field>
            <PermissionTip allowed={isGlobalAdmin(me)} action="alerts:write" reason="Needs a global admin">
              <SwitchField
                id="channel-allOrgs"
                label="All orgs"
                onText="Every org's events"
                offText="This org only"
                checked={draft.allOrgs}
                disabled={!isGlobalAdmin(me)}
                onCheckedChange={(allOrgs) => setDraft((d) => ({ ...d, allOrgs }))}
              />
            </PermissionTip>
          </FormSection>
          <SheetFooter className="flex-row justify-between gap-2 px-0">
            {channel ? (
              <PermissionTip allowed={canWrite} action="alerts:write" reason={writeReason}>
                <Button type="button" variant="destructive" disabled={!canWrite} onClick={() => setConfirmingDelete(true)}>
                  Delete
                </Button>
              </PermissionTip>
            ) : (
              <span />
            )}
            <span className="flex gap-2">
              <SheetClose asChild>
                <Button type="button" variant="outline">Cancel</Button>
              </SheetClose>
              <PermissionTip allowed={canWrite} action="alerts:write" reason={writeReason}>
                <Button type="submit" disabled={!canWrite || saving}>
                  Save
                </Button>
              </PermissionTip>
            </span>
          </SheetFooter>
        </form>
      </SheetContent>
      {channel && (
        <ConfirmDestructive
          open={confirmingDelete}
          onOpenChange={setConfirmingDelete}
          title="Delete channel?"
          consequence="Events stop going to this channel; past deliveries stay in the event log."
          confirmText={channel.name}
          actionLabel="Delete channel"
          onConfirm={async () => {
            await deleteChannel(channel);
            await qc.invalidateQueries({ queryKey: ['channels', orgId] });
            onOpenChange(false);
          }}
        />
      )}
    </Sheet>
  );
}
