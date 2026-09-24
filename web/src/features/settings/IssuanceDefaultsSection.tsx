import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { orgDefaultsQuery, useSaveOrgDefaults, effectiveDefaultsQuery } from '@/api/queries/defaults';
import { settingsQuery, useSaveSettings } from '@/api/queries/settings';
import { ApiError, errorMessage } from '@/api/errors';
import type { IssuanceDefaults } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { NO_ORG } from '@/lib/nav';
import { useMe } from '@/lib/org';
import { chainFor, fieldFromTitle, fromDefault, fromEffective, IssuanceDefaultsForm, useFieldCtx, type FieldKey } from './issuanceFields';

type ServerError = { field: FieldKey | null; message: string } | null;

function SaveRow({ label, dirty, busy, onSave, onDiscard, banner }: { label: string; dirty: boolean; busy: boolean; onSave: () => void; onDiscard: () => void; banner?: string | null }) {
  return (
    <div className="grid gap-2 pt-4">
      {banner && (
        <p role="alert" className="text-xs">
          {banner}
        </p>
      )}
      <div className="flex gap-2">
        <Button disabled={!dirty || busy} onClick={onSave}>
          {label}
        </Button>
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

export function IssuanceDefaultsSection() {
  const org = useMe().orgs[0];
  const ctx = useFieldCtx(org?.id ?? '');
  const globalQ = useQuery(settingsQuery('issuance_defaults'));
  const orgQ = useQuery({ ...orgDefaultsQuery(org?.id ?? ''), enabled: !!org });
  const effectiveQ = useQuery({ ...effectiveDefaultsQuery(org?.id ?? ''), enabled: !!org });
  const saveGlobal = useSaveSettings('issuance_defaults', { silent: true });
  const saveOrg = useSaveOrgDefaults(org?.id ?? '');
  const [globalDraft, setGlobalDraft] = useState<IssuanceDefaults | null>(null);
  const [orgDraft, setOrgDraft] = useState<IssuanceDefaults | null>(null);
  const [globalError, setGlobalError] = useState<ServerError>(null);
  const [orgError, setOrgError] = useState<ServerError>(null);

  const globalSaved = (globalQ.data?.value ?? {}) as IssuanceDefaults;
  const orgSaved = orgQ.data ?? {};
  const effective = effectiveQ.data ?? {};

  if (!org) return <p className="text-sm text-ink-muted">{NO_ORG}</p>;

  return (
    <Tabs defaultValue="org" className="max-w-[900px]">
      <div className="flex items-center gap-2">
        <TabsList>
          <TabsTrigger value="global">Global</TabsTrigger>
          <TabsTrigger value="org">{org.name}</TabsTrigger>
        </TabsList>
        <HelpTip id="defaults.inherit" />
      </div>
      <TabsContent value="global">
        <IssuanceDefaultsForm
          value={globalDraft ?? globalSaved}
          onChange={setGlobalDraft}
          inherited={fromDefault}
          ctx={ctx}
          error={(k) => (globalError?.field === k ? globalError.message : null)}
        />
        <SaveRow
          label="Save global defaults"
          dirty={!!globalDraft}
          busy={saveGlobal.isPending}
          banner={globalError && !globalError.field ? globalError.message : null}
          onSave={async () => {
            setGlobalError(null);
            try {
              await saveGlobal.mutateAsync(globalDraft as Record<string, unknown>);
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
          value={orgDraft ?? orgSaved}
          onChange={setOrgDraft}
          inherited={fromEffective(effective)}
          chain={chainFor(globalSaved, orgDraft ?? orgSaved, ctx)}
          ctx={ctx}
          error={(k) => (orgError?.field === k ? orgError.message : null)}
        />
        <SaveRow
          label="Save org defaults"
          dirty={!!orgDraft}
          busy={saveOrg.isPending}
          banner={orgError && !orgError.field ? orgError.message : null}
          onSave={async () => {
            setOrgError(null);
            try {
              await saveOrg.mutateAsync(orgDraft!);
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
