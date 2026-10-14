import { useMemo, useRef, useState } from 'react';
import type { RJSFSchema } from '@rjsf/utils';
import { CircleAlert } from 'lucide-react';
import { ApiError, errorMessage, fieldOfTitle } from '@/api/errors';
import { CREDENTIAL_KIND_LABEL, revealDeployCredentialSecret, useSaveDeployCredential } from '@/api/queries/deployCredentials';
import type { DeployCredential, DeployCredentialKind, ProviderSchema } from '@/api/types';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetClose, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, useSheetGuard, SheetBody } from '@/components/ui/sheet';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { fieldErrorFromMessage, secretKeys, withSecretSentinels } from '@/forms/uiSchema';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { stripSecretDefaults } from '@/lib/secretForm';
import { useDirty } from '@/lib/useDirty';

type Props = { orgId: string; credential?: DeployCredential; kinds: ProviderSchema[]; readOnly: boolean; onOpenChange: (open: boolean) => void };

/** The kind schema as a form: a root anyOf (ssh: password or private key)
 * would render RJSF's option picker, so it is left to the server's 422. */
export function kindFormSchema(kind: ProviderSchema | undefined): RJSFSchema {
  if (!kind) return { type: 'object', properties: {} };
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { anyOf, ...rest } = kind.schema as RJSFSchema;
  return stripSecretDefaults(rest);
}

export function CredentialSheet({ orgId, credential, kinds, readOnly, onOpenChange }: Props) {
  const guard = useSheetGuard(onOpenChange);
  const me = useMe();
  const save = useSaveDeployCredential(orgId);
  const formRef = useRef<SchemaFormHandle>(null);
  const [name, setName] = useState(credential?.name ?? '');
  const [kind, setKind] = useState<string>(credential?.kind ?? kinds[0]?.code ?? 'ssh');
  const kindMeta = kinds.find((k) => k.code === kind);
  const schema = useMemo(() => kindFormSchema(kindMeta), [kindMeta]);
  const storedSecrets = useMemo(() => credential?.storedSecrets ?? [], [credential]);
  const [config, setConfig] = useState<Record<string, unknown>>(() =>
    credential ? withSecretSentinels(kindFormSchema(kinds.find((k) => k.code === credential.kind)), credential.config ?? {}, credential.storedSecrets ?? []) : {},
  );
  const [nameError, setNameError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [extra, setExtra] = useState<ReturnType<typeof fieldErrorFromMessage>>(null);
  const dirty = useDirty({ name, kind, config });
  const credId = credential?.id;
  const onRevealSecret = useMemo(() => (credId ? (field: string) => revealDeployCredentialSecret(orgId, credId, field) : undefined), [orgId, credId]);
  const revealDisabledReason = can(me, 'deploycreds:reveal', orgId) ? undefined : 'Needs a global admin (deploycreds:reveal)';
  const title = credential ? (readOnly ? credential.name : `Edit ${credential.name}`) : 'Add credential';

  async function submit() {
    setFormError(null);
    const nameOk = name.trim() !== '';
    setNameError(nameOk ? null : 'Enter a name.');
    const formOk = formRef.current?.validate() ?? false;
    if (!nameOk || !formOk) return;
    const known = Object.keys(schema.properties ?? {});
    const body = {
      name: name.trim(),
      kind: kind as DeployCredentialKind,
      // Cleared fields (undefined or '') are left out; a removed stored secret is deleted that way.
      config: Object.fromEntries(Object.entries(config).filter(([k, v]) => known.includes(k) && v !== undefined && v !== null && v !== '')),
    };
    try {
      await save.mutateAsync({ id: credential?.id, body });
      guard.close();
    } catch (e) {
      const msg = errorMessage(e);
      const field = e instanceof ApiError ? fieldOfTitle(e.problem.title) : null;
      const schemaField = fieldErrorFromMessage(schema, msg);
      if (field === 'name' || (e instanceof ApiError && e.status === 409)) setNameError(msg);
      else if (schemaField) setExtra(schemaField);
      else setFormError(msg);
    }
  }

  return (
    <Sheet guard={guard} open form={!readOnly} dirty={dirty} onOpenChange={onOpenChange}>
      <SheetContent side="right" size="md">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription className="sr-only">Deploy credential</SheetDescription>
        </SheetHeader>
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <SheetBody>
            <Field id="dcred-name" label="Name" error={nameError}>
              <Input
                id="dcred-name"
                value={name}
                placeholder="lab ssh key"
                autoComplete="off"
                disabled={readOnly}
                onChange={(e) => {
                  setName(e.target.value);
                  setNameError(null);
                }}
              />
            </Field>
            <Field id="dcred-kind" label="Kind" help="deployCred.kind">
              <SegmentedControl<string>
                id="dcred-kind"
                aria-label="Kind"
                value={kind}
                onChange={(v) => {
                  setKind(v);
                  setConfig({});
                  setExtra(null);
                }}
                options={kinds.map((k) => ({
                  value: k.code,
                  label: CREDENTIAL_KIND_LABEL[k.code] ?? k.name,
                  disabled: !!credential || readOnly,
                  hint: credential ? 'Fixed once the credential exists.' : undefined,
                }))}
              />
            </Field>
            <div className="grid gap-1.5">
              <span className="inline-flex items-center gap-1.5 text-sm font-semibold">
                Fields
                {secretKeys(schema).length > 0 && <HelpTip id="target.secrets" />}
              </span>
              <SchemaForm
                key={kind}
                ref={formRef}
                schema={schema}
                value={config}
                onChange={(v) => {
                  setConfig(v);
                  setExtra(null);
                }}
                storedSecrets={credential?.kind === kind ? storedSecrets : []}
                readonly={readOnly}
                extraErrors={extra ?? undefined}
                onRevealSecret={onRevealSecret}
                revealDisabledReason={revealDisabledReason}
              />
            </div>
            {formError && (
              <p role="alert" className="flex items-center gap-1.5 text-sm">
                <CircleAlert className="size-4 text-failed" aria-hidden />
                {formError}
              </p>
            )}
          </SheetBody>
          <SheetFooter>
            {readOnly ? (
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                Close
              </Button>
            ) : (
              <>
                <SheetClose asChild>
                  <Button type="button" variant="outline">
                    Cancel
                  </Button>
                </SheetClose>
                <Button type="submit" disabled={save.isPending}>
                  Save credential
                </Button>
              </>
            )}
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
