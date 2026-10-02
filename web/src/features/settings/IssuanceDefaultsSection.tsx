import { useEffect, useState } from 'react';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import type { LevelLinks } from '@/forms/InheritableField';
import { orgDefaultsQuery, useSaveOrgDefaults, effectiveDefaultsQuery } from '@/api/queries/defaults';
import { settingsQuery, useSaveSettings } from '@/api/queries/settings';
import { ApiError, errorMessage } from '@/api/errors';
import type { IssuanceDefaults, Org } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Combobox } from '@/components/Combobox';
import { FilterField } from '@/components/FilterToolbar';
import { SegmentedControl, type SegmentOption } from '@/components/SegmentedControl';
import { orgsQuery } from '@/api/queries/orgs';
import { NO_ORG } from '@/lib/nav';
import { useActiveOrgSlug, useMe } from '@/lib/org';
import { can, isGlobalAdmin, type Action } from '@/lib/permissions';
import { builtinStateOf, chainFor, fieldFromTitle, fromBuiltin, fromEffective, fullPayload, globalPayload, IssuanceDefaultsForm, useFieldCtx, type FieldKey } from './issuanceFields';
import { SchemaSection } from './SchemaSection';

// Task 9: placeholders for the four rate-limit inputs; the fields themselves
// (title, description/tooltip, min/max) come straight from the server's
// `issuance` schema.
const RATE_LIMIT_UI = { 'ui:placeholder': '0' };
const ISSUANCE_UI_OVERRIDES = {
  rateLimits: {
    'ui:classNames': 'grid gap-3 sm:grid-cols-2',
    certsPerRegisteredDomainPerWeek: RATE_LIMIT_UI,
    duplicateCertsPerWeek: RATE_LIMIT_UI,
    failedValidationsPerHour: RATE_LIMIT_UI,
    newOrdersPer3Hours: RATE_LIMIT_UI,
  },
};

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
    <div className="grid gap-2 py-4">
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

const linksFor = (slug: string): { global: LevelLinks; org: LevelLinks } => ({
  global: { org: `/settings/issuance-defaults?scope=org&org=${encodeURIComponent(slug)}` },
  org: { global: '/settings/issuance-defaults?scope=global' },
});

const SCOPES: SegmentOption<'global' | 'org'>[] = [
  { value: 'global', label: 'Global' },
  { value: 'org', label: 'Organization' },
];

function GlobalScope({ org, links }: { org: Org; links: LevelLinks }) {
  const me = useMe();
  const canWriteGlobal = can(me, 'settings:write', null);
  const ctx = useFieldCtx(org.id);
  // The Global scope's issuance defaults aren't org-scoped, so its own
  // verification-rules editor never offers a client picker; agentModes: false
  // also disables tls-alpn-01/http-01-via-agent there, since an empty client
  // list alone still let them be picked and 422 on Save.
  const globalCtx: typeof ctx = { ...ctx, clients: [], agentModes: false };
  const globalQ = useQuery(settingsQuery('issuance_defaults'));
  const effectiveQ = useQuery(effectiveDefaultsQuery(org.id));
  const saveGlobal = useSaveSettings('issuance_defaults', { silent: true });
  const [globalDraft, setGlobalDraft] = useState<IssuanceDefaults | null>(null);
  const [globalError, setGlobalError] = useState<ServerError>(null);
  // The shipped values come from the server (effective endpoint's `builtin`);
  // `stored` (null until the section was ever saved) is the edit buffer.
  const builtin = effectiveQ.data?.builtin as IssuanceDefaults | undefined;
  const builtinState = builtinStateOf(effectiveQ);
  const globalStored = (globalQ.data?.stored ?? null) as IssuanceDefaults | null;
  return (
    <div className="grid gap-4">
    <IssuanceDefaultsForm
      value={globalDraft ?? globalStored ?? {}}
      onChange={setGlobalDraft}
      level="global"
      links={links}
      chain={chainFor(builtin, globalStored ?? {}, undefined, globalCtx)}
      inherited={fromBuiltin(builtin)}
      builtinState={builtinState}
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
          await saveGlobal.mutateAsync(globalPayload(globalDraft ?? globalStored ?? {}, globalStored, builtin) as Record<string, unknown>);
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
    <SchemaSection section="issuance" title="Checks and limits" help="settings.issuanceChecks" uiSchemaOverrides={ISSUANCE_UI_OVERRIDES} />
    </div>
  );
}

function OrgScope({ org, links }: { org: Org; links: LevelLinks }) {
  const me = useMe();
  const canWriteOrg = can(me, 'certs:write', org.id);
  const ctx = useFieldCtx(org.id);
  const orgQ = useQuery(orgDefaultsQuery(org.id));
  const effectiveQ = useQuery(effectiveDefaultsQuery(org.id));
  const globalQ = useQuery(settingsQuery('issuance_defaults'));
  const saveOrg = useSaveOrgDefaults(org.id);
  const [orgDraft, setOrgDraft] = useState<IssuanceDefaults | null>(null);
  const [orgError, setOrgError] = useState<ServerError>(null);
  const builtin = effectiveQ.data?.builtin as IssuanceDefaults | undefined;
  const builtinState = builtinStateOf(effectiveQ);
  const globalStored = (globalQ.data?.stored ?? null) as IssuanceDefaults | null;
  const orgSaved = orgQ.data ?? {};
  const effective = effectiveQ.data ?? {};
  const orgValue = orgDraft ?? orgSaved;
  return (
    <div className="grid gap-4">
    <IssuanceDefaultsForm
      value={orgValue}
      onChange={setOrgDraft}
      level="org"
      links={links}
      inherited={fromEffective(effective)}
      builtinState={builtinState}
      // The hover chain's Global entry comes from the raw stored value
      // (review fix round 1, #2), not the built-in-filled
      // display — otherwise a field the badge calls 'Default' would
      // still show a concrete "Global: …" line in its own tooltip.
      chain={chainFor(builtin, globalStored ?? {}, orgValue, ctx)}
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
    </div>
  );
}

export function IssuanceDefaultsSection() {
  const me = useMe();
  const search = useSearch({ from: '/_app/settings/$section' });
  const navigate = useNavigate({ from: '/settings/$section' });
  const activeSlug = useActiveOrgSlug();
  const scope = search.scope ?? 'global';
  // A global admin may open any org; everyone else only their own.
  const orgsQ = useQuery({ ...orgsQuery, enabled: isGlobalAdmin(me) });
  const orgs: Org[] = (isGlobalAdmin(me) ? orgsQ.data : undefined) ?? me.orgs;
  const wanted = orgs.find((o) => o.slug === (search.org ?? activeSlug));
  const listReady = !isGlobalAdmin(me) || !orgsQ.isPending;
  const fallbackSlug = (wanted ?? orgs[0])?.slug;
  const badOrg = !!search.org && !orgs.some((o) => o.slug === search.org) && listReady && !!fallbackSlug;
  useEffect(() => {
    if (badOrg) void navigate({ search: (prev) => ({ ...prev, org: fallbackSlug }), replace: true });
  }, [badOrg, fallbackSlug, navigate]);
  // A deep-linked org may not be in me.orgs for a global admin: wait for the full list instead of flashing the first org.
  if (!wanted && search.org && isGlobalAdmin(me) && orgsQ.isPending) return <p className="text-sm text-ink-muted">Loading…</p>;
  const org = wanted ?? orgs[0];
  if (!org) return <p className="text-sm text-ink-muted">{NO_ORG}</p>;
  const links = linksFor(org.slug);
  const go = (patch: { scope?: 'global' | 'org'; org?: string }) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });
  return (
    <div className="grid max-w-[900px] gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <FilterField label="Scope">
          <SegmentedControl aria-label="Defaults scope" value={scope} onChange={(v) => go({ scope: v })} options={SCOPES} />
        </FilterField>
        {scope === 'org' && (
          <div className="w-64 max-w-full">
            <Combobox
              aria-label="Organization"
              value={org.slug}
              clearable={false}
              onChange={(slug) => slug && go({ org: slug })}
              options={orgs.map((o) => ({ value: o.slug, label: o.name, hint: o.slug === o.name ? undefined : o.slug }))}
              placeholder="Choose organization"
              emptyText="No matching organizations"
            />
          </div>
        )}
        <HelpTip id="defaults.inherit" />
      </div>
      {scope === 'org' ? <OrgScope key={org.id} org={org} links={links.org} /> : <GlobalScope key="global" org={org} links={links.global} />}
    </div>
  );
}
