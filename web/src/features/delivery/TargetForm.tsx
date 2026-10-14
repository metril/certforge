import { useDirty } from '@/lib/useDirty';
import { useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import type { ErrorSchema, RJSFSchema } from '@rjsf/utils';
import { CircleAlert, Cpu, Server as ServerIcon } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { createDeployTarget, layoutsQuery, updateDeployTarget } from '@/api/queries/delivery';
import { invalidateGrants } from '@/api/queries/grants';
import { CREDENTIAL_KIND_LABEL, deployCredentialsQuery, suppliedFields } from '@/api/queries/deployCredentials';
import { UNCHANGED, type DeployTarget, type ProviderSchema } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { PermissionTip } from '@/components/PermissionTip';
import { RunsOnChip } from '@/components/RunsOnChip';
import { SegmentedControl, type SegmentOption } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { FormActions, FormPage } from '@/components/FormPage';
import { useNavBypass } from '@/components/NavGuard';
import { FormSection } from '@/components/FormSection';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { plural } from '@/api/queries/certificates';
import { fieldErrorFromMessage, secretKeys } from '@/forms/uiSchema';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { caBundleScope, can } from '@/lib/permissions';
import { stripSecretDefaults, storedSecretsFor, settledConfig } from '@/lib/secretForm';
import { RUNS_ON_META, credentialKindsOf, defaultRunsOn, forcedRunsOn, keyGateBlocks, locationChanged, toTargetInput, typeHelpKey, typeMeta, unrequireFields } from '@/lib/targets';
import { useMediaQuery } from '@/lib/useMediaQuery';

function omitKeys(o: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));
}

type Props = { orgId: string; orgSlug: string; target?: DeployTarget; types: ProviderSchema[]; /** Read-only: just the sections, no page chrome (the detail Overview tab). */ readOnly?: boolean };

/** Create / edit form for a deploy target: a full page (FormPage) or, read-only, bare sections. */
export function TargetForm({ orgId, orgSlug, target, types, readOnly = false }: Props) {
  const bypass = useNavBypass();
  const navigate = useNavigate();
  const me = useMe();
  const qc = useQueryClient();
  const isSmUp = useMediaQuery('(min-width: 640px)');
  const formRef = useRef<SchemaFormHandle>(null);
  const [name, setName] = useState(target?.name ?? '');
  const [type, setType] = useState<string>(target?.type ?? types[0]!.code);
  const initialMeta = typeMeta(types, target?.type ?? types[0]!.code) ?? types[0]!;
  const [runsOn, setRunsOn] = useState<'server' | 'agent'>(target?.runsOn ?? defaultRunsOn(initialMeta));
  const [config, setConfig] = useState<Record<string, unknown>>((target?.config as Record<string, unknown> | undefined) ?? {});
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [extra, setExtra] = useState<ErrorSchema | null>(null);
  const [saving, setSaving] = useState(false);
  const meta = useMemo(() => typeMeta(types, type) ?? types[0]!, [types, type]);
  const fullSchema = useMemo(() => stripSecretDefaults(meta.schema as RJSFSchema), [meta]);
  // Saved credentials: a type with credentialKinds can take its login from one.
  const credKinds = useMemo(() => credentialKindsOf(meta.schema), [meta]);
  const canCredWrite = can(me, 'deploycreds:write', orgId);
  const credsQ = useQuery({ ...deployCredentialsQuery(orgId), enabled: credKinds.length > 0 && can(me, 'deploycreds:read', orgId) });
  const initialCredId = target?.credentialId ?? null;
  const [credentialId, setCredentialId] = useState<string | null>(initialCredId);
  const credentials = useMemo(() => (credsQ.data ?? []).filter((c) => credKinds.includes(c.kind)), [credsQ.data, credKinds]);
  const credential = credentialId ? credentials.find((c) => c.id === credentialId) : undefined;
  // Wait for the list before showing the form, so a credential's fields never flash in.
  const credPending = !!credentialId && credsQ.isPending;
  // Attaching a credential clears the target's own stored secrets, so none are kept.
  const storedSecrets = useMemo(() => (credentialId !== initialCredId ? [] : storedSecretsFor(target, type)), [credentialId, initialCredId, target, type]);
  // Fields the credential supplies stay on the form, read-only and filled from it.
  const supplied = useMemo(() => {
    const props = (fullSchema.properties ?? {}) as Record<string, unknown>;
    return credential ? suppliedFields(credential).filter((k) => k in props) : [];
  }, [credential, fullSchema]);
  const schema = useMemo(() => unrequireFields(fullSchema, supplied), [fullSchema, supplied]);
  const formValue = useMemo(() => {
    if (!credential) return config;
    const out = { ...config, ...credential.config };
    for (const k of credential.storedSecrets ?? []) if (supplied.includes(k)) out[k] = UNCHANGED;
    return out;
  }, [config, credential, supplied]);
  const formStored = useMemo(() => [...new Set([...storedSecrets, ...(credential?.storedSecrets ?? []).filter((k) => supplied.includes(k))])], [storedSecrets, credential, supplied]);
  // Settled so the form's mount-time onChange (defaults, secret sentinels) is not an edit.
  const dirty = useDirty({ name, type, runsOn, credentialId, config: omitKeys(settledConfig(schema, omitKeys(config, supplied), storedSecrets), supplied) });
  const canExportKeys = can(me, 'keys:export', orgId);
  const layoutsQ = useQuery({ ...layoutsQuery(orgId), enabled: type === 'ssh' });
  // The SSH files editor suggests layout file names: the dispatcher resolves
  // a file's content by the base name of the layout path.
  const sshContentNames = useMemo(() => {
    const seen = new Set(['fullchain', 'cert', 'chain', 'key', 'bundle']);
    const out: { name: string; layout: string }[] = [];
    for (const l of layoutsQ.data ?? []) {
      for (const f of l.files) {
        const name = f.path.split('/').pop() ?? '';
        if (name === '' || seen.has(name)) continue;
        seen.add(name);
        out.push({ name, layout: l.name });
      }
    }
    return out;
  }, [layoutsQ.data]);
  const formContext = useMemo(
    () => ({ caBundle: caBundleScope(me, orgId), sshHostKey: { orgId, canPeek: can(me, 'delivery:write', orgId) }, sshContentNames }),
    [me, orgId, sshContentNames],
  );
  // Locked once the target exists (R3: runsOn/type are immutable after
  // create) or for a viewer opening it read-only.
  const locked = !!target || readOnly;
  const forced = forcedRunsOn(meta);
  // An either type whose key policy is always needs keys:export the moment
  // Server is picked (UI conventions "either default"); optional-policy
  // gating (includeKey) happens on the switch itself, not here.
  const keyGateServer = meta.runsOn === 'either' && meta.keyPolicy === 'always' && !canExportKeys;
  const title = target ? `Edit ${target.name}` : 'Add deploy target';

  function runsOnOption(mode: 'server' | 'agent'): Pick<SegmentOption<'server' | 'agent'>, 'disabled' | 'hint'> {
    if (locked) return { disabled: true, hint: help['target.runsOnLocked'].text };
    if (forced && forced !== mode) return { disabled: true, hint: help['target.runsOnForced'].text };
    if (mode === 'server' && keyGateServer) return { disabled: true, hint: 'Needs the keys:export permission' };
    return { disabled: false };
  }

  const changeType = (v: string | undefined) => {
    if (!v) return;
    const newMeta = typeMeta(types, v) ?? types[0]!;
    setType(v);
    setConfig({});
    setCredentialId(null);
    setRunsOn(defaultRunsOn(newMeta));
    setExtra(null);
    setFormError(null);
  };

  const includeKeyOverride =
    schema.properties && 'includeKey' in schema.properties
      ? { includeKey: { 'ui:description': help['target.includeKey'].text, 'ui:options': { permission: 'keys:export', allowed: runsOn !== 'server' || canExportKeys } } }
      : undefined;

  const suppliedUi = supplied.length > 0 ? Object.fromEntries(supplied.map((k) => [k, { 'ui:disabled': true, 'ui:description': 'From the credential' }])) : undefined;
  const uiOverrides = includeKeyOverride || suppliedUi ? { ...includeKeyOverride, ...suppliedUi } : undefined;

  const blocked = keyGateBlocks(me, orgId, runsOn, meta.keyPolicy, config);
  // Attaching a credential, or moving a credential-backed target to another
  // host, port or hostKey, also needs deploycreds:write (the server returns 403 otherwise).
  const credBlocked =
    !canCredWrite &&
    ((credentialId !== null && credentialId !== initialCredId) ||
      (initialCredId !== null && credentialId === initialCredId && locationChanged(schema, (target?.config as Record<string, unknown> | undefined) ?? {}, config)));

  const pickCredential = (v: string | undefined) => {
    const id = !v || v === 'manual' ? null : v;
    setCredentialId(id);
    setExtra(null);
    setFormError(null);
  };

  const submit = async () => {
    setFormError(null);
    const nameOk = name.trim() !== '';
    setNameError(nameOk ? null : 'Enter a name.');
    const formOk = formRef.current?.validate() ?? false;
    if (!nameOk || !formOk) return;
    setSaving(true);
    try {
      const body = toTargetInput({ name, type, runsOn, config: omitKeys(config, supplied) }, schema, storedSecrets, !target);
      if (credKinds.length > 0) body.credentialId = credentialId;
      const saved = target ? await updateDeployTarget(orgId, target.id, body) : await createDeployTarget(orgId, body);
      toast.success('Deploy target saved');
      await Promise.all([qc.invalidateQueries({ queryKey: ['deploy-targets', orgId] }), invalidateGrants(qc, orgId)]);
      bypass.current = true;
      void navigate({ to: '/o/$org/delivery/targets/$id/$tab', params: { org: orgSlug, id: target?.id ?? saved.id, tab: 'overview' } });
    } catch (e) {
      const msg = errorMessage(e);
      const field = fieldErrorFromMessage(schema, msg);
      if (field) setExtra(field);
      // Only a name conflict ("A deploy target named ... already exists" —
      // the server's detail names the target) belongs under Name; a 409 on
      // a config path collision (two targets writing the same directory)
      // names a path or another target, not "name", and reads better as a
      // page-level alert than silently attached to the wrong field.
      else if (e instanceof ApiError && e.status === 409 && /name/i.test(msg)) setNameError(msg);
      else setFormError(msg);
    } finally {
      setSaving(false);
    }
  };

  const sections = (
    <>
      <FormSection title="General" columns={2}>
      <Field id="target-name" label="Name" error={nameError}>
        <Input
          id="target-name"
          value={name}
          placeholder="edge traefik"
          autoComplete="off"
          disabled={readOnly}
          onChange={(e) => {
            setName(e.target.value);
            setNameError(null);
          }}
        />
      </Field>
      <Field id="target-type" label="Type" help={typeHelpKey(type)} className={types.length <= 5 ? 'sm:col-span-2' : undefined}>
        {types.length <= 5 ? (
          <SegmentedControl<string>
            id="target-type"
            aria-label="Type"
            value={type}
            onChange={changeType}
            options={types.map((t) => ({
              value: t.code,
              label: (
                <span className="inline-flex items-center gap-1.5">
                  {t.name}
                  <RunsOnChip mode={t.runsOn ?? 'agent'} compact={!isSmUp} />
                </span>
              ),
              disabled: locked,
            }))}
          />
        ) : (
          <Combobox
            id="target-type"
            aria-label="Type"
            value={type}
            onChange={changeType}
            options={types.map((t) => ({ value: t.code, label: t.name, hint: RUNS_ON_META[t.runsOn ?? 'agent'].label }))}
            placeholder="Pick a type"
            emptyText="No type matches."
            disabled={locked}
          />
        )}
      </Field>
      <Field id="target-runs-on" label="Runs on" help="target.runsOn">
        <SegmentedControl<'server' | 'agent'>
          id="target-runs-on"
          aria-label="Runs on"
          value={runsOn}
          onChange={setRunsOn}
          options={[
            {
              value: 'server',
              label: (
                <>
                  <ServerIcon className="size-4" aria-hidden />
                  Server
                </>
              ),
              ...runsOnOption('server'),
            },
            {
              value: 'agent',
              label: (
                <>
                  <Cpu className="size-4" aria-hidden />
                  Agent
                </>
              ),
              ...runsOnOption('agent'),
            },
          ]}
        />
      </Field>
      {credKinds.length > 0 && (
        <Field id="target-credential" label="Credential" help="target.credential">
          {(() => {
            const select = (
              <Combobox
                id="target-credential"
                aria-label="Credential"
                value={credentialId ?? 'manual'}
                onChange={pickCredential}
                options={[{ value: 'manual', label: 'Enter manually' }, ...credentials.map((c) => ({ value: c.id, label: c.name, hint: CREDENTIAL_KIND_LABEL[c.kind] ?? c.kind }))]}
                placeholder="Enter manually"
                emptyText="No saved credential matches."
                disabled={readOnly || !canCredWrite}
              />
            );
            if (readOnly || canCredWrite) return select;
            return (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span tabIndex={0} className="grid">
                    {select}
                  </span>
                </TooltipTrigger>
                <TooltipContent>Needs the deploycreds:write permission</TooltipContent>
              </Tooltip>
            );
          })()}
        </Field>
      )}
    </FormSection>
    <FormSection title="Connection" help={secretKeys(schema).length > 0 ? 'target.secrets' : undefined}>
      {credPending ? (
        <p className="py-4 text-sm text-ink-muted">Loading…</p>
      ) : (
        <SchemaForm
          key={credentialId ?? 'manual'}
          ref={formRef}
          schema={schema}
          value={formValue}
          onChange={(v) => {
            setConfig(omitKeys(v, supplied));
            setExtra(null);
          }}
          storedSecrets={formStored}
          readonly={readOnly}
          extraErrors={extra ?? undefined}
          uiSchemaOverrides={uiOverrides}
          formContext={formContext}
          columns={2}
        />
      )}
    </FormSection>
    </>
  );
  if (readOnly) return <div className="grid gap-4">{sections}</div>;

  const credName = credential?.name;
  const rail = (
    <dl className="grid gap-3 text-sm">
      <div className="grid gap-1">
        <dt className="text-xs text-ink-muted">Type</dt>
        <dd className="flex flex-wrap items-center gap-2">
          {meta.name}
          <RunsOnChip mode={runsOn} />
        </dd>
      </div>
      {credKinds.length > 0 && (
        <div className="grid gap-1">
          <dt className="text-xs text-ink-muted">Credential</dt>
          <dd className="truncate">{credName ?? 'Entered manually'}</dd>
        </div>
      )}
      {target && (
        <div className="grid gap-1">
          <dt className="text-xs text-ink-muted">Used by</dt>
          <dd>{plural(target.grantCount, 'grant')}</dd>
        </div>
      )}
    </dl>
  );
  const backTo = target
    ? { label: target.name, link: { to: '/o/$org/delivery/targets/$id/$tab', params: { org: orgSlug, id: target.id, tab: 'overview' } } as const }
    : { label: 'Deploy targets', link: { to: '/o/$org/delivery/targets', params: { org: orgSlug } } as const };

  return (
    <FormPage
      title={title}
      backTo={backTo}
      dirty={dirty}
      bypass={bypass}
      rail={rail}
      actions={
        <FormActions
          onCancel={() => void navigate(backTo.link)}
          save={
            <PermissionTip allowed={!blocked && !credBlocked} action={blocked ? 'keys:export' : 'deploycreds:write'}>
              <Button disabled={blocked || credBlocked || saving || credPending} onClick={() => void submit()}>
                Save
              </Button>
            </PermissionTip>
          }
        />
      }
    >
      {sections}
      {formError && (
        <p role="alert" className="flex items-center gap-1.5 text-sm">
          <CircleAlert className="size-4 text-failed" aria-hidden />
          {formError}
        </p>
      )}
    </FormPage>
  );
}
