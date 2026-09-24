import { useMemo, useRef, useState } from 'react';
import type { RJSFSchema } from '@rjsf/utils';
import { useSaveCredential } from '@/api/queries/dns';
import { ApiError, errorMessage } from '@/api/errors';
import type { DnsCredential, DnsCredentialInput, ProviderSchema } from '@/api/types';
import { UNCHANGED } from '@/api/types';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { secretKeys, withSecretSentinels } from '@/forms/uiSchema';

type Props = {
  orgId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  provider?: ProviderSchema;
  credential?: DnsCredential;
  onSaved?: (c: DnsCredential) => void;
  onChangeProvider?: () => void;
};

// The server rejects a PUT that changes a non-secret config value while any
// secret is still __unchanged__ (internal/issuance/store_dnscreds.go
// UpdateDNSCredential): "secrets must be re-entered when connection settings
// change". Its 422 carries `title: "Invalid " + field`, `detail: msg` (no
// separate structured field), so the field name is read back out of the title.
function fieldFromTitle(title: string | undefined): string | null {
  return title?.startsWith('Invalid ') ? title.slice('Invalid '.length) : null;
}

export function CredentialSheet({ orgId, open, onOpenChange, provider, credential, onSaved, onChangeProvider }: Props) {
  const save = useSaveCredential(orgId);
  const formRef = useRef<SchemaFormHandle>(null);
  const schema = useMemo(() => (provider?.schema ?? { type: 'object', properties: {} }) as RJSFSchema, [provider]);
  const storedSecrets = useMemo(() => credential?.storedSecrets ?? [], [credential]);
  const secretKeyList = useMemo(() => secretKeys(schema), [schema]);
  const nonSecretKeys = useMemo(() => Object.keys(schema.properties ?? {}).filter((k) => !secretKeyList.includes(k)), [schema, secretKeyList]);
  const initialPublic = useRef<Record<string, string>>(credential?.config ?? {});

  const [name, setName] = useState(credential?.name ?? provider?.name ?? '');
  const [config, setConfig] = useState<Record<string, unknown>>(() =>
    credential ? withSecretSentinels(schema, (credential.config ?? {}) as Record<string, unknown>, storedSecrets) : {},
  );
  const [submitted, setSubmitted] = useState(false);
  const [serverError, setServerError] = useState<{ field: string | null; message: string } | null>(null);

  // Controller ruling: on update, touching a non-secret config value while a
  // secret is still stored (untouched, sentinel-valued) is guaranteed to fail
  // that same server check, so warn before the round trip rather than only
  // after the 422.
  const publicChanged = !!credential && nonSecretKeys.some((k) => String(config[k] ?? '') !== String(initialPublic.current[k] ?? ''));
  const secretsStillUnchanged = !!credential && storedSecrets.some((k) => config[k] === UNCHANGED);
  const showSecretsNotice = publicChanged && secretsStillUnchanged;

  async function submit() {
    setSubmitted(true);
    setServerError(null);
    const formOk = formRef.current?.validate() ?? true;
    if (!provider || !name.trim() || !formOk) return;
    const body: DnsCredentialInput = {
      name: name.trim(),
      providerCode: provider.code,
      config: Object.fromEntries(Object.entries(config).map(([k, v]) => [k, String(v)])),
    };
    try {
      const saved = await save.mutateAsync({ id: credential?.id, body });
      onSaved?.(saved);
      onOpenChange(false);
    } catch (e) {
      const field = e instanceof ApiError ? fieldFromTitle(e.problem.title) : null;
      setServerError({ field, message: errorMessage(e) });
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{credential ? `Edit ${credential.name}` : `Add ${provider?.name ?? 'DNS'} credential`}</SheetTitle>
          <SheetDescription className="sr-only">DNS provider credential</SheetDescription>
        </SheetHeader>
        <form
          className="grid gap-5 px-4"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <div className="flex items-center gap-2 text-sm">
            <span className="font-semibold">{provider?.name}</span>
            <span className="font-mono text-xs text-ink-muted">{provider?.code}</span>
            <HelpTip id="dns.provider" />
            {!credential && onChangeProvider && (
              <Button type="button" variant="link" size="sm" className="ml-auto px-0" onClick={onChangeProvider}>
                Change provider
              </Button>
            )}
          </div>
          <Field id="cred-name" label="Name" error={submitted && !name.trim() ? 'Required' : serverError?.field === 'name' ? serverError.message : null}>
            <Input id="cred-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Cloudflare prod" />
          </Field>
          <SchemaForm ref={formRef} schema={schema} value={config} onChange={setConfig} storedSecrets={storedSecrets} />
          {showSecretsNotice && (
            <p className="text-xs text-ink-muted">Connection settings changed — stored secrets above must be re-entered before saving.</p>
          )}
          {serverError && serverError.field !== 'name' && (
            <p role="alert" className="text-xs">
              {serverError.message}
            </p>
          )}
          <SheetFooter className="px-0">
            <Button type="submit" disabled={save.isPending}>
              Save credential
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
