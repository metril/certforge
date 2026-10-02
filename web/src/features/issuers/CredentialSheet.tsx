import { useDirty } from '@/lib/useDirty';
import { useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { meQuery } from '@/api/queries/auth';
import { CircleAlert } from 'lucide-react';
import type { RJSFSchema } from '@rjsf/utils';
import { revealCredentialSecret, useSaveCredential } from '@/api/queries/dns';
import { ApiError, errorMessage } from '@/api/errors';
import type { DnsCredential, DnsCredentialInput, ProviderSchema } from '@/api/types';
import { UNCHANGED } from '@/api/types';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { FormSection } from '@/components/FormSection';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { advancedSchema, authMethodsOf, hasAdvancedValue, inferMethod, methodKeys, methodSchema } from '@/forms/authMethods';
import { can } from '@/lib/permissions';
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
  // useMe() needs the router context, which the certificate wizard's create-only
  // use of this sheet lacks; the cached me query serves both (no fetch on create).
  const me = useQuery({ ...meQuery, enabled: !!credential }).data;
  const credId = credential?.id;
  const onRevealSecret = useMemo(
    () => (credId ? (field: string) => revealCredentialSecret(orgId, credId, field) : undefined),
    [orgId, credId],
  );
  const revealDisabledReason = !me || !can(me, 'dnscreds:reveal', orgId) ? 'Needs a global admin (dnscreds:reveal)' : undefined;
  const formRef = useRef<SchemaFormHandle>(null);
  const schema = useMemo(() => (provider?.schema ?? { type: 'object', properties: {} }) as RJSFSchema, [provider]);
  const storedSecrets = useMemo(() => credential?.storedSecrets ?? [], [credential]);
  const secretKeyList = useMemo(() => secretKeys(schema), [schema]);
  const methods = useMemo(() => authMethodsOf(schema), [schema]);
  const advSchema = useMemo(() => advancedSchema(schema), [schema]);
  const advKeys = useMemo(() => Object.keys(advSchema.properties ?? {}), [advSchema]);
  const initialPublic = useRef<Record<string, string>>(credential?.config ?? {});

  const [name, setName] = useState(credential?.name ?? provider?.name ?? '');
  const [config, setConfig] = useState<Record<string, unknown>>(() =>
    credential ? withSecretSentinels(schema, (credential.config ?? {}) as Record<string, unknown>, storedSecrets) : {},
  );
  const [methodId, setMethodId] = useState<string | undefined>(() =>
    inferMethod(methods, (credential?.config ?? {}) as Record<string, unknown>, storedSecrets)?.id,
  );
  const method = methods.find((m) => m.id === methodId) ?? methods[0];
  const mainSchema = useMemo(() => (method ? methodSchema(schema, method) : schema), [schema, method]);
  const [advOpen] = useState(() => hasAdvancedValue(schema, (credential?.config ?? {}) as Record<string, unknown>));
  const mainKeys = useMemo(() => Object.keys(mainSchema.properties ?? {}), [mainSchema]);
  // Each form sees and edits only its own keys; the rest of `config` is kept.
  const pick = (keys: string[]) => Object.fromEntries(Object.entries(config).filter(([k]) => keys.includes(k)));
  const mergeOwn = (keys: string[]) => (data: Record<string, unknown>) =>
    setConfig((prev) => ({ ...Object.fromEntries(Object.entries(prev).filter(([k]) => !keys.includes(k))), ...data }));
  const advFormRef = useRef<SchemaFormHandle>(null);
  const shownKeys = useMemo(() => (method ? [...methodKeys(method), ...advKeys] : Object.keys(schema.properties ?? {})), [method, advKeys, schema]);
  const nonSecretKeys = useMemo(() => shownKeys.filter((k) => !secretKeyList.includes(k)), [shownKeys, secretKeyList]);
  const [submitted, setSubmitted] = useState(false);
  const [serverError, setServerError] = useState<{ field: string | null; message: string } | null>(null);
  const dirty = useDirty({ name, config, methodId });

  // Controller ruling: on update, touching a non-secret config value while a
  // secret is still stored (untouched, sentinel-valued) is guaranteed to fail
  // that same server check, so warn before the round trip rather than only
  // after the 422.
  const publicChanged = !!credential && nonSecretKeys.some((k) => String(config[k] ?? '') !== String(initialPublic.current[k] ?? ''));
  const secretsStillUnchanged = !!credential && storedSecrets.some((k) => config[k] === UNCHANGED);
  const showSecretsNotice = publicChanged && secretsStillUnchanged;

  // Keep values for keys both methods share (and non-method keys like the
  // Advanced ones); drop the rest, stored-secret sentinels included. A stored
  // secret the new method shows is re-seeded so switching back keeps it.
  function switchMethod(id: string) {
    const next = methods.find((m) => m.id === id);
    if (!next || next.id === method?.id) return;
    const nextKeys = new Set(methodKeys(next));
    const anyMethodKey = new Set(methods.flatMap(methodKeys));
    const kept = Object.fromEntries(Object.entries(config).filter(([k]) => nextKeys.has(k) || !anyMethodKey.has(k)));
    const seeded = credential ? withSecretSentinels(schema, kept, storedSecrets.filter((k) => nextKeys.has(k))) : kept;
    setMethodId(id);
    setConfig(seeded);
  }

  async function submit() {
    setSubmitted(true);
    setServerError(null);
    const mainOk = formRef.current?.validate() ?? true;
    const advOk = advFormRef.current?.validate() ?? true;
    const formOk = mainOk && advOk;
    if (!provider || !name.trim() || !formOk) return;
    const body: DnsCredentialInput = {
      name: name.trim(),
      providerCode: provider.code,
      // Fix round 1 (Important): RJSF 6.10 keeps `{key: undefined}` in
      // formData when a field is cleared (its default text widget sets
      // `options.emptyValue`, which is `undefined`) rather than dropping the
      // key — Object.entries then still visits it, and `String(undefined)`
      // is the literal string "undefined", which the server would store as
      // the value (a secret included). Cleared/never-set entries are
      // dropped instead; an untouched stored secret keeps sending
      // UNCHANGED (a real, non-empty string), so it's unaffected.
      config: Object.fromEntries(
        Object.entries(config)
          .filter(([k]) => !method || shownKeys.includes(k))
          .filter(([, v]) => v !== undefined && v !== null && v !== '')
          .map(([k, v]) => [k, String(v)]),
      ),
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
    <Sheet open={open} form dirty={dirty} onOpenChange={onOpenChange}>
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
          {methods.length > 1 && (
            <div className="grid gap-1.5">
              <div className="flex items-center gap-1.5 text-sm font-medium">
                Authenticate with <HelpTip id="dns.authMethod" />
              </div>
              <SegmentedControl
                aria-label="Authenticate with"
                value={method?.id ?? ''}
                onChange={switchMethod}
                options={methods.map((m) => ({ value: m.id, label: m.label }))}
              />
            </div>
          )}
          {method && method.fields.length === 0 && method.optional.length === 0 ? (
            <p className="text-sm text-ink-muted">Uses the server&apos;s own environment credentials.</p>
          ) : (
            <SchemaForm key={method?.id} ref={formRef} schema={mainSchema} value={method ? pick(mainKeys) : config} onChange={method ? mergeOwn(mainKeys) : setConfig} storedSecrets={storedSecrets} onRevealSecret={onRevealSecret} revealDisabledReason={revealDisabledReason} />
          )}
          {advKeys.length > 0 && (
            <FormSection
              title="Advanced"
              collapsible
              defaultOpen={advOpen}
              count={advKeys.filter((k) => config[k] !== undefined && config[k] !== '').length}
              forceOpen={!!serverError?.field && advKeys.includes(serverError.field)}
            >
              <SchemaForm ref={advFormRef} schema={advSchema} value={pick(advKeys)} onChange={mergeOwn(advKeys)} storedSecrets={storedSecrets} onRevealSecret={onRevealSecret} revealDisabledReason={revealDisabledReason} />
            </FormSection>
          )}
          {showSecretsNotice && (
            <p className="text-xs text-ink-muted">Connection settings changed — stored secrets above must be re-entered before saving.</p>
          )}
          {serverError && serverError.field !== 'name' && (
            // Fix round 1: same CircleAlert + text-failed treatment as
            // TestCredentialDialog's inline error, not a plain unstyled line.
            <p role="alert" className="flex items-center gap-1.5 text-sm">
              <CircleAlert className="size-4 text-failed" aria-hidden />
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
