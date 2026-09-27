import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { orgDefaultsQuery, useSaveOrgDefaults, effectiveDefaultsQuery } from '@/api/queries/defaults';
import { settingsQuery, useSaveSettings } from '@/api/queries/settings';
import { ApiError, errorMessage } from '@/api/errors';
import type { IssuanceDefaults } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { NO_ORG } from '@/lib/nav';
import { useMe } from '@/lib/org';
import { can, type Action } from '@/lib/permissions';
import { chainFor, fieldFromTitle, fromBuiltin, fromEffective, fullPayload, IssuanceDefaultsForm, useFieldCtx, type FieldKey } from './issuanceFields';

type ServerError = { field: FieldKey | null; message: string } | null;

function SaveRow({
  label,
  dirty,
  busy,
  onSave,
  onDiscard,
  banner,
  canWrite,
  permAction,
}: {
  label: string;
  dirty: boolean;
  busy: boolean;
  onSave: () => void;
  onDiscard: () => void;
  banner?: string | null;
  canWrite: boolean;
  permAction: Action;
}) {
  return (
    <div className="grid gap-2 pt-4">
      {banner && (
        <p role="alert" className="text-xs">
          {banner}
        </p>
      )}
      <div className="flex gap-2">
        <PermissionTip allowed={canWrite} action={permAction}>
          <Button disabled={!dirty || busy || !canWrite} onClick={onSave}>
            {label}
          </Button>
        </PermissionTip>
        {dirty && (
          <Button variant="ghost" onClick={onDiscard}>
            Discard changes
          </Button>
        )}
      </div>
    </div>
  );
}

/** Maps a thrown save error to its field (the 422's title is always
 * "Invalid <field>", see internal/api/issuance_common.go's mapErr /
 * unprocessable) so InheritableField can show it next to that field; an
 * unmapped error (or a non-ApiError, e.g. a network failure) falls back to
 * the row's banner. */
function mapError(e: unknown): ServerError {
  const field = e instanceof ApiError ? fieldFromTitle(e.problem.title ?? '') : null;
  return { field, message: errorMessage(e) };
}

/** The banner shows an error that has nowhere else to go: one that never
 * mapped to a field, or one that mapped to a field whose InheritableField
 * isn't overridden right now (so it renders no editor row to attach the
 * error to) — review fix round 1 (#5): a mapped field must not silently
 * suppress the banner just because it's currently hidden. */
function bannerFor(error: ServerError, value: IssuanceDefaults): string | null {
  if (!error) return null;
  if (!error.field) return error.message;
  return value[error.field] == null ? error.message : null;
}

export function IssuanceDefaultsSection() {
  const me = useMe();
  const org = me.orgs[0];
  const canWriteGlobal = can(me, 'settings:write', null);
  const canWriteOrg = can(me, 'certs:write', org?.id ?? null);
  const ctx = useFieldCtx(org?.id ?? '');
  // The Global tab's issuance defaults aren't org-scoped, so its own
  // verification-rules editor never offers a client picker — clients live
  // per org (FieldCtx.clients, allClientsQuery(orgId)); the Org tab below
  // keeps the real, org-scoped list.
  const globalCtx: typeof ctx = { ...ctx, clients: [] };
  const globalQ = useQuery(settingsQuery('issuance_defaults'));
  const orgQ = useQuery({ ...orgDefaultsQuery(org?.id ?? ''), enabled: !!org });
  const effectiveQ = useQuery({ ...effectiveDefaultsQuery(org?.id ?? ''), enabled: !!org });
  const saveGlobal = useSaveSettings('issuance_defaults', { silent: true });
  const saveOrg = useSaveOrgDefaults(org?.id ?? '');
  const [globalDraft, setGlobalDraft] = useState<IssuanceDefaults | null>(null);
  const [orgDraft, setOrgDraft] = useState<IssuanceDefaults | null>(null);
  const [globalError, setGlobalError] = useState<ServerError>(null);
  const [orgError, setOrgError] = useState<ServerError>(null);

  // globalValue is the built-in-filled display value (GET's `value`); it is
  // never the edit buffer or the "is this overridden" source of truth.
  // globalStored (GET's `stored`, null until the section has ever been
  // saved) is both, instead (controller ruling, review fix round 1, #1):
  // before this fix, the filled-in globalValue was used for both, so every
  // field looked already overridden and the first edit re-saved every
  // built-in as an explicit 'global' value.
  const globalValue = (globalQ.data?.value ?? {}) as IssuanceDefaults;
  const globalStored = (globalQ.data?.stored ?? null) as IssuanceDefaults | null;
  const orgSaved = orgQ.data ?? {};
  const effective = effectiveQ.data ?? {};
  const orgValue = orgDraft ?? orgSaved;

  if (!org) return <p className="text-sm text-ink-muted">{NO_ORG}</p>;

  return (
    <Tabs defaultValue="org" className="max-w-[900px]">
      <div className="flex flex-wrap items-center gap-2">
        <TabsList>
          <TabsTrigger value="global">Global</TabsTrigger>
          <TabsTrigger value="org">{org.name}</TabsTrigger>
        </TabsList>
        <HelpTip id="defaults.inherit" />
      </div>
      <TabsContent value="global">
        <div className="mb-3 flex items-center gap-1.5">
          <span className="text-sm font-medium">Built-in defaults</span>
          <HelpTip id="defaults.globalBuiltin" />
        </div>
        <IssuanceDefaultsForm
          value={globalDraft ?? globalStored ?? {}}
          onChange={setGlobalDraft}
          inherited={fromBuiltin(globalValue)}
          ctx={globalCtx}
          error={(k) => (globalError?.field === k ? globalError.message : null)}
        />
        <SaveRow
          label="Save global defaults"
          dirty={!!globalDraft}
          busy={saveGlobal.isPending}
          canWrite={canWriteGlobal}
          permAction="settings:write"
          banner={bannerFor(globalError, globalDraft ?? globalStored ?? {})}
          onSave={async () => {
            setGlobalError(null);
            try {
              await saveGlobal.mutateAsync(fullPayload(globalDraft ?? globalStored ?? {}) as Record<string, unknown>);
              setGlobalDraft(null);
            } catch (e) {
              setGlobalError(mapError(e));
            }
          }}
          onDiscard={() => {
            setGlobalDraft(null);
            setGlobalError(null);
          }}
        />
      </TabsContent>
      <TabsContent value="org">
        <IssuanceDefaultsForm
          value={orgValue}
          onChange={setOrgDraft}
          inherited={fromEffective(effective)}
          // The hover chain's Global entry comes from the raw stored value
          // (review fix round 1, #2), not globalValue's built-in-filled
          // display — otherwise a field the badge calls 'Default' would
          // still show a concrete "Global: …" line in its own tooltip.
          chain={chainFor(globalStored ?? {}, orgValue, ctx)}
          ctx={ctx}
          error={(k) => (orgError?.field === k ? orgError.message : null)}
          // A field just reset to inherited (orgDraft explicitly null) whose
          // last-saved org value was set is "inherited after save", not yet
          // reflected by `effective` (review fix round 1, #3).
          pending={(k) => orgDraft != null && orgDraft[k] == null && orgSaved[k] != null}
        />
        <SaveRow
          label="Save org defaults"
          dirty={!!orgDraft}
          busy={saveOrg.isPending}
          canWrite={canWriteOrg}
          permAction="certs:write"
          banner={bannerFor(orgError, orgValue)}
          onSave={async () => {
            setOrgError(null);
            try {
              await saveOrg.mutateAsync(fullPayload(orgValue));
              setOrgDraft(null);
            } catch (e) {
              setOrgError(mapError(e));
            }
          }}
          onDiscard={() => {
            setOrgDraft(null);
            setOrgError(null);
          }}
        />
      </TabsContent>
    </Tabs>
  );
}
