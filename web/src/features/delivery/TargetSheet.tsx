import { useRef, useState } from 'react';
import type { ErrorSchema, RJSFSchema } from '@rjsf/utils';
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

type Props = { orgId: string; target?: DeployTarget; types: ProviderSchema[]; readOnly: boolean; onOpenChange: (open: boolean) => void };

export function TargetSheet({ orgId, target, types, readOnly, onOpenChange }: Props) {
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
      else if (e instanceof ApiError && e.status === 409) setNameError(msg);
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
          <Field id="target-type" label="Type" help="target.type">
            {types.length <= 5 ? (
              <SegmentedControl<string>
                id="target-type"
                aria-label="Type"
                value={type}
                onChange={changeType}
                options={types.map((t) => ({ value: t.code, label: t.name, disabled: !!target || readOnly }))}
              />
            ) : (
              <Combobox
                id="target-type"
                aria-label="Type"
                value={type}
                onChange={changeType}
                options={types.map((t) => ({ value: t.code, label: t.name }))}
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
          />
          {formError && (
            <p role="alert" className="text-sm">
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
