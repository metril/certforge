import { useMemo, useRef, useState } from 'react';
import type { ErrorSchema, RJSFSchema } from '@rjsf/utils';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage } from '@/api/errors';
import { useSaveDeployTarget } from '@/api/queries/delivery';
import type { DeployTarget, DeployTargetInput, ProviderSchema } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { Field } from '@/components/Field';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { fieldErrorFromMessage } from '@/forms/uiSchema';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';

type Props = { orgId: string; target?: DeployTarget; types: ProviderSchema[]; readOnly: boolean; onOpenChange: (open: boolean) => void };

// Task 8: the only server-run target type today (deploy.RunsOn mirrors this
// same single-type check server-side); a target's own `runsOn` (derived from
// its type) isn't in GET /meta/schemas' entries, only on a saved DeployTarget.
const SERVER_TYPES = new Set(['vault-kv']);
const runsOnHint = (code: string) => (SERVER_TYPES.has(code) ? 'Runs on server' : 'Runs on agent');

export function TargetSheet({ orgId, target, types, readOnly, onOpenChange }: Props) {
  const me = useMe();
  const save = useSaveDeployTarget(orgId);
  const formRef = useRef<SchemaFormHandle>(null);
  const [name, setName] = useState(target?.name ?? '');
  const [type, setType] = useState<string>(target?.type ?? types[0]!.code);
  const [config, setConfig] = useState<Record<string, unknown>>((target?.config as Record<string, unknown> | undefined) ?? {});
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [extra, setExtra] = useState<ErrorSchema | null>(null);
  const schema = (types.find((t) => t.code === type) ?? types[0]!).schema as RJSFSchema;
  const title = target ? (readOnly ? target.name : `Edit ${target.name}`) : 'Add deploy target';
  const changeType = (v: string | undefined) => {
    if (!v) return;
    setType(v);
    setConfig({});
    setExtra(null);
  };
  const canExportKeys = can(me, 'keys:export', orgId);
  // vault-kv's own uiSchema: includeKey gated behind keys:export, keys/path
  // in the mono font, path's placeholder (the schema's `default`, which
  // buildUiSchema doesn't surface as a placeholder).
  const uiSchemaOverrides = useMemo(() => {
    if (type !== 'vault-kv') return undefined;
    return {
      // Batch 4 review: target.includeKey existed but was never referenced —
      // wired in here as the switch's own tooltip (widgets.tsx's SwitchWidget
      // now prefers options.description, which getUiOptions fills from
      // ui:description) instead of the schema's own shorter description.
      includeKey: { 'ui:description': help['target.includeKey'].text, 'ui:options': { permission: 'keys:export', allowed: canExportKeys } },
      path: { 'ui:options': { mono: true }, 'ui:placeholder': 'certforge/{org}/{name}' },
      keys: {
        fullchain: { 'ui:options': { mono: true } },
        cert: { 'ui:options': { mono: true } },
        chain: { 'ui:options': { mono: true } },
        key: { 'ui:options': { mono: true } },
      },
    };
  }, [type, canExportKeys]);

  const submit = async () => {
    setFormError(null);
    const nameOk = name.trim() !== '';
    setNameError(nameOk ? null : 'Enter a name.');
    const formOk = formRef.current?.validate() ?? false;
    if (!nameOk || !formOk) return;
    try {
      await save.mutateAsync({ id: target?.id, body: { name: name.trim(), type: type as DeployTargetInput['type'], config } });
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
    }
  };

  return (
    <Sheet open onOpenChange={onOpenChange}>
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
          <Field id="target-type" label="Type" help={type === 'vault-kv' ? 'target.vaultKv' : 'target.type'}>
            {types.length <= 5 ? (
              <SegmentedControl<string>
                id="target-type"
                aria-label="Type"
                value={type}
                onChange={changeType}
                options={types.map((t) => ({ value: t.code, label: t.name, disabled: !!target || readOnly, hint: runsOnHint(t.code) }))}
              />
            ) : (
              <Combobox
                id="target-type"
                aria-label="Type"
                value={type}
                onChange={changeType}
                options={types.map((t) => ({ value: t.code, label: t.name, hint: runsOnHint(t.code) }))}
                placeholder="Pick a type"
                emptyText="No type matches."
                disabled={!!target || readOnly}
              />
            )}
          </Field>
          <SchemaForm
            ref={formRef}
            schema={schema}
            value={config}
            onChange={(v) => {
              setConfig(v);
              setExtra(null);
            }}
            readonly={readOnly}
            extraErrors={extra ?? undefined}
            uiSchemaOverrides={uiSchemaOverrides}
          />
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
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button disabled={save.isPending} onClick={() => void submit()}>
                Save
              </Button>
            </>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
