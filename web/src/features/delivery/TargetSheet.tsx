import { useDirty } from '@/lib/useDirty';
import { useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { ErrorSchema, RJSFSchema } from '@rjsf/utils';
import { CircleAlert, Cpu, Server as ServerIcon } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { createDeployTarget, updateDeployTarget } from '@/api/queries/delivery';
import { invalidateGrants } from '@/api/queries/grants';
import type { DeployTarget, ProviderSchema } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { RunsOnChip } from '@/components/RunsOnChip';
import { SegmentedControl, type SegmentOption } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetClose } from '@/components/ui/sheet';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { fieldErrorFromMessage, secretKeys } from '@/forms/uiSchema';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { stripSecretDefaults, storedSecretsFor } from '@/lib/secretForm';
import { RUNS_ON_META, defaultRunsOn, forcedRunsOn, keyGateBlocks, toTargetInput, typeHelpKey, typeMeta } from '@/lib/targets';
import { useMediaQuery } from '@/lib/useMediaQuery';

type Props = { orgId: string; target?: DeployTarget; types: ProviderSchema[]; readOnly: boolean; onOpenChange: (open: boolean) => void };

export function TargetSheet({ orgId, target, types, readOnly, onOpenChange }: Props) {
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
  const dirty = useDirty({ name, type, runsOn, config });

  const meta = useMemo(() => typeMeta(types, type) ?? types[0]!, [types, type]);
  const schema = useMemo(() => stripSecretDefaults(meta.schema as RJSFSchema), [meta]);
  const canExportKeys = can(me, 'keys:export', orgId);
  // Locked once the target exists (R3: runsOn/type are immutable after
  // create) or for a viewer opening it read-only.
  const locked = !!target || readOnly;
  const forced = forcedRunsOn(meta);
  // An either type whose key policy is always needs keys:export the moment
  // Server is picked (UI conventions "either default"); optional-policy
  // gating (includeKey) happens on the switch itself, not here.
  const keyGateServer = meta.runsOn === 'either' && meta.keyPolicy === 'always' && !canExportKeys;
  const title = target ? (readOnly ? target.name : `Edit ${target.name}`) : 'Add deploy target';

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
    setRunsOn(defaultRunsOn(newMeta));
    setExtra(null);
    setFormError(null);
  };

  const includeKeyOverride =
    schema.properties && 'includeKey' in schema.properties
      ? { includeKey: { 'ui:description': help['target.includeKey'].text, 'ui:options': { permission: 'keys:export', allowed: runsOn !== 'server' || canExportKeys } } }
      : undefined;

  const blocked = keyGateBlocks(me, orgId, runsOn, meta.keyPolicy, config);

  const submit = async () => {
    setFormError(null);
    const nameOk = name.trim() !== '';
    setNameError(nameOk ? null : 'Enter a name.');
    const formOk = formRef.current?.validate() ?? false;
    if (!nameOk || !formOk) return;
    setSaving(true);
    try {
      const body = toTargetInput({ name, type, runsOn, config }, schema, storedSecretsFor(target, type), !target);
      if (target) await updateDeployTarget(orgId, target.id, body);
      else await createDeployTarget(orgId, body);
      toast.success('Deploy target saved');
      await Promise.all([qc.invalidateQueries({ queryKey: ['deploy-targets', orgId] }), invalidateGrants(qc, orgId)]);
      onOpenChange(false);
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

  return (
    <Sheet open form={!readOnly} dirty={dirty} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription className="sr-only">Deploy target settings</SheetDescription>
        </SheetHeader>
        <div className="grid gap-5 px-4">
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
          <Field id="target-type" label="Type" help={typeHelpKey(type)}>
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
                { value: 'server', label: <><ServerIcon className="size-4" aria-hidden />Server</>, ...runsOnOption('server') },
                { value: 'agent', label: <><Cpu className="size-4" aria-hidden />Agent</>, ...runsOnOption('agent') },
              ]}
            />
          </Field>
          <div className="grid gap-1.5">
            <span className="inline-flex items-center gap-1.5 text-sm font-semibold">
              Settings
              {secretKeys(schema).length > 0 && <HelpTip id="target.secrets" />}
            </span>
            <SchemaForm
              ref={formRef}
              schema={schema}
              value={config}
              onChange={(v) => {
                setConfig(v);
                setExtra(null);
              }}
              storedSecrets={storedSecretsFor(target, type)}
              readonly={readOnly}
              extraErrors={extra ?? undefined}
              uiSchemaOverrides={includeKeyOverride}
            />
          </div>
          {formError && (
            <p role="alert" className="flex items-center gap-1.5 text-sm">
              <CircleAlert className="size-4 text-failed" aria-hidden />
              {formError}
            </p>
          )}
        </div>
        <SheetFooter className="flex-row justify-end gap-2">
          {readOnly ? (
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Close
            </Button>
          ) : (
            <>
              <SheetClose asChild>
                <Button variant="outline">Cancel</Button>
              </SheetClose>
              <PermissionTip allowed={!blocked} action="keys:export">
                <Button disabled={blocked || saving} onClick={() => void submit()}>
                  Save
                </Button>
              </PermissionTip>
            </>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
