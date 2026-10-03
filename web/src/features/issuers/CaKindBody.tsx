import { useMemo, type Dispatch, type RefObject, type SetStateAction } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Check, TriangleAlert } from 'lucide-react';
import type { ErrorSchema, RJSFSchema } from '@rjsf/utils';
import { settingsQuery } from '@/api/queries/settings';
import type { CA, CAPreset, ProviderSchema } from '@/api/types';
import { Field } from '@/components/Field';
import { HelpTip } from '@/components/HelpTip';
import { ListInput } from '@/components/ListInput';
import { SecretInput } from '@/components/SecretInput';
import { SwitchField } from '@/components/SwitchField';
import { FormSection } from '@/components/FormSection';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { SchemaForm, type SchemaFormHandle } from '@/forms/SchemaForm';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import type { AcmeDraft, CaDraft } from './caBody';

const CUSTOM = 'custom';

const isHttps = (v: string) => {
  try {
    return new URL(v).protocol === 'https:';
  } catch {
    return false;
  }
};
// `[v6]:port`, `[v6]`, a bare IPv6 address, or `host[:port]`; the port, when
// given, must be 1-65535.
export const hostPort = (v: string) => {
  const bad = `${v} is not host or host:port`;
  if (/^[0-9a-fA-F:.]+$/.test(v) && /[0-9a-fA-F]/.test(v) && !v.includes(":::") && (v.match(/:/g) ?? []).length >= 2) return null;
  const m = /^\[[0-9a-fA-F:.]+\](?::(\d{1,5}))?$/.exec(v) ?? /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?::(\d{1,5}))?$/.exec(v);
  if (!m) return bad;
  return m[1] === undefined || (Number(m[1]) >= 1 && Number(m[1]) <= 65535) ? null : bad;
};

export type ServerField = 'name' | 'directoryUrl' | 'eab' | null;

type Props = {
  draft: CaDraft;
  setDraft: Dispatch<SetStateAction<CaDraft>>;
  ca?: CA;
  presets: CAPreset[];
  signers: ProviderSchema[];
  submitted: boolean;
  serverError: { field: ServerField; message: string } | null;
  extraErrors?: ErrorSchema;
  formRef: RefObject<SchemaFormHandle>;
  /** Whether the operator has typed into the shared Name field themselves —
   * a fresh preset pick auto-fills Name only while it's still untouched (or
   * whatever a previous preset set it to). Owned by CaSheet, since Name
   * itself renders there, above the kind body. */
  nameTouched: boolean;
};

export function CaKindBody({ draft, setDraft, ca, presets, signers, submitted, serverError, extraErrors, formRef, nameTouched }: Props) {
  if (draft.kind === 'acme') {
    return <AcmeBody draft={draft} setDraft={setDraft} ca={ca} presets={presets} submitted={submitted} serverError={serverError} nameTouched={nameTouched} />;
  }
  if (draft.kind === 'localca') {
    return <LocalCaBody draft={draft} setDraft={setDraft} ca={ca} signers={signers} extraErrors={extraErrors} formRef={formRef} />;
  }
  return <VaultPkiBody draft={draft} setDraft={setDraft} signers={signers} extraErrors={extraErrors} formRef={formRef} />;
}

function AcmeBody({
  draft,
  setDraft,
  ca,
  presets,
  submitted,
  serverError,
  nameTouched,
}: {
  draft: CaDraft;
  setDraft: Dispatch<SetStateAction<CaDraft>>;
  ca?: CA;
  presets: CAPreset[];
  submitted: boolean;
  serverError: { field: ServerField; message: string } | null;
  nameTouched: boolean;
}) {
  const form = draft.acme;
  const set = <K extends keyof AcmeDraft>(k: K, v: AcmeDraft[K]) => setDraft((d) => ({ ...d, acme: { ...d.acme, [k]: v } }));

  const preset = presets.find((p) => p.preset === form.preset);
  const custom = form.preset === CUSTOM;
  const showEab = custom || !!preset?.requiresEab;
  const errors = {
    preset: form.preset ? null : 'Choose a preset or Custom',
    directoryUrl: isHttps(form.directoryUrl) ? null : 'Use an https:// URL',
    eab: preset?.requiresEab && (!form.eabKid.trim() || !form.eabHmac) ? 'This CA requires external account binding' : null,
  };
  const errFor = (key: Exclude<ServerField, null>, clientErr: string | null): string | null =>
    (submitted ? clientErr : null) ??
    // Fix round 1 (#6, carried from the pre-5B CaSheet): a 422 mapped to the
    // EAB field while its fieldset is hidden would otherwise render nowhere;
    // the generic banner below handles that case.
    (serverError?.field === key && (key !== 'eab' || showEab) ? serverError.message : null);

  function pickPreset(p: CAPreset) {
    // Fix round 2 (carried): re-clicking the already-selected preset card is
    // not a switch — it must not wipe EAB values the operator already typed.
    if (p.preset === form.preset) return;
    setDraft((d) => ({
      ...d,
      // Fix round 1 (#1, carried): an existing CA's name was typed by
      // someone, and a fresh preset pick shouldn't clobber a name the
      // operator has already edited by hand.
      name: nameTouched ? d.name : p.name,
      acme: {
        ...d.acme,
        preset: p.preset,
        directoryUrl: p.directoryUrl,
        // Fix round 1 (#1, carried): a previous preset's EAB kid/HMAC must
        // not survive a switch.
        eabKid: '',
        eabHmac: undefined,
      },
    }));
  }

  const card = (key: string, title: string, sub: string, eab: boolean, onPick: () => void) => {
    const on = form.preset === key;
    return (
      <button
        key={key}
        type="button"
        aria-pressed={on}
        onClick={onPick}
        className={cn('grid gap-0.5 rounded-md border p-3 text-left', on ? 'border-primary bg-primary/8' : 'border-border hover:bg-subtle')}
      >
        <span className="flex items-center gap-1.5 text-sm font-semibold">
          {on && <Check className="size-3.5 text-primary" aria-hidden />}
          {title}
          {eab && <span className="rounded-sm bg-subtle px-1 text-xs font-normal">EAB</span>}
        </span>
        <span className="truncate font-mono text-xs text-ink-muted">{sub}</span>
      </button>
    );
  };

  return (
    <>
      <fieldset className="grid gap-2">
        <legend className="mb-2 flex items-center gap-1.5 text-sm font-semibold">
          Preset <HelpTip id="ca.preset" />
        </legend>
        <div className="grid grid-cols-2 gap-2">
          {presets.map((p) =>
            // Adaptation (preflight A20, carried): `custom` is one of the 7
            // presets the API returns (directoryUrl: ''), not a card this
            // component adds itself.
            card(p.preset, p.name, p.preset === CUSTOM ? 'Any ACME directory' : new URL(p.directoryUrl).host, p.requiresEab, () => pickPreset(p)),
          )}
        </div>
        {submitted && errors.preset && <p className="text-xs">{errors.preset}</p>}
      </fieldset>
      {form.preset && (
        <>
          <Field id="ca-dir" label="Directory URL" help="ca.directoryUrl" error={errFor('directoryUrl', errors.directoryUrl)}>
            <Input
              id="ca-dir"
              className="font-mono text-xs"
              value={form.directoryUrl}
              onChange={(e) => set('directoryUrl', e.target.value)}
              placeholder="https://ca.example.com/acme/directory"
            />
          </Field>
          {custom && (
            <Field id="ca-trust" label="Trust bundle" help="ca.importTrustBundle" optional>
              <Textarea
                id="ca-trust"
                rows={5}
                className="font-mono text-xs"
                value={form.trustBundlePem}
                onChange={(e) => set('trustBundlePem', e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </Field>
          )}
          {showEab && (
            <fieldset className="grid gap-3">
              <legend className="mb-1 flex items-center gap-1.5 text-sm font-semibold">
                External account binding <HelpTip id="ca.eab" />
              </legend>
              <Field id="ca-eab-kid" label="Key ID" optional={custom}>
                <Input id="ca-eab-kid" className="font-mono text-xs" value={form.eabKid} onChange={(e) => set('eabKid', e.target.value)} placeholder="kid_3xAmPlE" />
              </Field>
              <Field id="ca-eab-hmac" label="HMAC key" optional={custom} error={errFor('eab', errors.eab)}>
                <SecretInput id="ca-eab-hmac" label="HMAC key" stored={!!ca?.hasEab} value={form.eabHmac} onChange={(v) => set('eabHmac', v)} />
              </Field>
            </fieldset>
          )}
          <FormSection title="Advanced" collapsible count={form.resolvers.length > 0 ? 1 : 0} forceOpen={submitted && form.resolvers.some((r) => !!hostPort(r))}>
            <Field id="ca-resolvers" label="Resolvers" help="ca.resolvers" optional>
              <ListInput id="ca-resolvers" value={form.resolvers} onChange={(v) => set('resolvers', v)} placeholder="1.1.1.1:53" validate={hostPort} />
            </Field>
          </FormSection>
        </>
      )}
      {serverError && (!serverError.field || (serverError.field === 'eab' && !showEab)) && (
        <p role="alert" className="text-xs">
          {serverError.message}
        </p>
      )}
    </>
  );
}

function schemaOf(signers: ProviderSchema[], code: string): RJSFSchema {
  return (signers.find((s) => s.code === code)?.schema ?? { type: 'object', properties: {} }) as RJSFSchema;
}

function LocalCaBody({
  draft,
  setDraft,
  ca,
  signers,
  extraErrors,
  formRef,
}: {
  draft: CaDraft;
  setDraft: Dispatch<SetStateAction<CaDraft>>;
  ca?: CA;
  signers: ProviderSchema[];
  extraErrors?: ErrorSchema;
  formRef: RefObject<SchemaFormHandle>;
}) {
  const editing = !!ca;
  const { config, importing } = draft.localca;
  const baseSchema = useMemo(() => schemaOf(signers, 'localca'), [signers]);
  // Importing: `subject`/`keyType`/the validity years come from the
  // imported certificate itself, never typed by the operator, so they're
  // dropped from the schema entirely rather than left present-but-hidden —
  // `subject` carries its own nested `required: ['commonName']`, and RJSF
  // still validates a hidden object field against that subschema whenever
  // it's present in formData (e.g. left over from before the switch was
  // turned on), even once the outer schema no longer lists `subject` itself
  // as required. Dropping the properties outright means there's nothing
  // left to validate. The server's own schema always lists `subject` as
  // required (5a-facts.md) — that requirement is for the generate path.
  const schema = useMemo(() => {
    if (editing || !importing) return baseSchema;
    const drop = new Set(['subject', 'keyType', 'rootValidityYears', 'issuingValidityYears']);
    const properties = Object.fromEntries(Object.entries(baseSchema.properties ?? {}).filter(([k]) => !drop.has(k)));
    return { ...baseSchema, required: [], properties };
  }, [baseSchema, importing, editing]);
  const uiSchemaOverrides = useMemo(() => {
    if (editing) {
      return {
        subject: { 'ui:readonly': true },
        keyType: { 'ui:readonly': true },
        rootValidityYears: { 'ui:readonly': true },
        issuingValidityYears: { 'ui:readonly': true },
        importPem: { 'ui:widget': 'hidden' },
        importKeyPem: { 'ui:widget': 'hidden' },
      };
    }
    if (importing) {
      return {
        subject: { 'ui:widget': 'hidden' },
        keyType: { 'ui:widget': 'hidden' },
        rootValidityYears: { 'ui:widget': 'hidden' },
        issuingValidityYears: { 'ui:widget': 'hidden' },
        importPem: { 'ui:widget': 'textarea' },
        importKeyPem: { 'ui:widget': 'textarea' },
      };
    }
    return { importPem: { 'ui:widget': 'hidden' }, importKeyPem: { 'ui:widget': 'hidden' } };
  }, [editing, importing]);

  return (
    <>
      {!editing && (
        <SwitchField
          id="ca-import"
          label="Import existing CA"
          help="ca.import"
          checked={importing}
          onCheckedChange={(v) =>
            setDraft((d) => {
              // The switched-away half's fields are dropped from formData,
              // not just hidden — otherwise they linger as keys the other
              // half's schema (subject/keyType/validity years absent
              // entirely when importing, `additionalProperties: false`)
              // rejects outright as "False boolean schema" on validate.
              const c = { ...(d.localca.config as Record<string, unknown>) };
              for (const k of v ? ['subject', 'keyType', 'rootValidityYears', 'issuingValidityYears'] : ['importPem', 'importKeyPem']) delete c[k];
              return { ...d, localca: { config: c, importing: v } };
            })
          }
        />
      )}
      <SchemaForm
        ref={formRef}
        schema={schema}
        value={config}
        onChange={(v) => setDraft((d) => ({ ...d, localca: { ...d.localca, config: v } }))}
        storedSecrets={ca?.storedSecrets}
        extraErrors={extraErrors}
        uiSchemaOverrides={uiSchemaOverrides}
      />
    </>
  );
}

function VaultPkiBody({
  draft,
  setDraft,
  signers,
  extraErrors,
  formRef,
}: {
  draft: CaDraft;
  setDraft: Dispatch<SetStateAction<CaDraft>>;
  signers: ProviderSchema[];
  extraErrors?: ErrorSchema;
  formRef: RefObject<SchemaFormHandle>;
}) {
  const me = useMe();
  const canReadSettings = can(me, 'settings:read', null);
  const vaultQ = useQuery({ ...settingsQuery('vault'), enabled: canReadSettings });
  const schema = useMemo(() => schemaOf(signers, 'vaultpki'), [signers]);
  const notConfigured = canReadSettings && vaultQ.data !== undefined && !vaultQ.data.value?.address;

  return (
    <>
      <SchemaForm
        ref={formRef}
        schema={schema}
        value={draft.vaultpki.config}
        onChange={(v) => setDraft((d) => ({ ...d, vaultpki: { config: v } }))}
        extraErrors={extraErrors}
      />
      {notConfigured && (
        <p className="flex items-center gap-1.5 text-xs text-ink-muted">
          <TriangleAlert className="size-3.5 text-expiring" aria-hidden />
          Vault is not configured.{' '}
          <Link to="/settings/$section" params={{ section: 'integrations' }} className="underline underline-offset-2">
            Settings → Integrations
          </Link>
        </p>
      )}
    </>
  );
}
