import { useEffect, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { accountsQuery } from '@/api/queries/accounts';
import { casQuery } from '@/api/queries/cas';
import { allClientsQuery } from '@/api/queries/clients';
import { dnsCredentialsQuery } from '@/api/queries/dns';
import type { AcmeAccount, CA, Client, DnsCredential, EffectiveMap, EffectiveValue, IssuanceDefaults, KeyType, Source, VerificationRule } from '@/api/types';
import { Combobox } from '@/components/Combobox';
import { ListInput } from '@/components/ListInput';
import { SegmentedControl, type SegmentOption } from '@/components/SegmentedControl';
import { SwitchField } from '@/components/SwitchField';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { InheritableField, type ChainEntry } from '@/forms/InheritableField';
import { VerificationRulesEditor } from '@/forms/VerificationRulesEditor';
import { isPrivate, KIND_LABEL } from '@/lib/caKinds';
import type { HelpKey } from '@/lib/help';
import { ruleTarget } from '@/lib/rules';

// Clients are org-scoped (allClientsQuery(orgId)); the Global tab has no
// single org to ask, so IssuanceDefaultsSection passes an empty list there,
// plus agentModes: false (review fix round 1, Important) — otherwise
// tls-alpn-01/http-01-via-agent stay pickable there with no client that
// could ever satisfy them, and Save 422s.
export type FieldCtx = { cas: CA[]; accounts: AcmeAccount[]; credentials: DnsCredential[]; clients: Client[]; agentModes?: boolean };
export type FieldKey = keyof IssuanceDefaults;
type V<K extends FieldKey> = NonNullable<IssuanceDefaults[K]>;

export type IssuanceField = {
  key: FieldKey;
  label: string;
  help: HelpKey;
  initial: (c: FieldCtx) => unknown;
  display: (v: unknown, c: FieldCtx) => ReactNode;
  // set accepts null (review fix round 1, #4): a lookup editor's own clear
  // affordance means "unset" (reset to inherited), not "set to an empty
  // string" (which the API always 422s).
  editor: (v: unknown, set: (v: unknown | null) => void, c: FieldCtx, id: string) => ReactNode;
  /** When set, Override cannot be turned on for this field (e.g. an empty CA list has nothing to pick) — an already-overridden field can still be reset. */
  disabledReason?: (c: FieldCtx) => string | undefined;
};

export function def<K extends FieldKey>(d: {
  key: K;
  label: string;
  help: HelpKey;
  initial: (c: FieldCtx) => V<K>;
  display: (v: V<K>, c: FieldCtx) => ReactNode;
  editor: (v: V<K>, set: (v: V<K> | null) => void, c: FieldCtx, id: string) => ReactNode;
  disabledReason?: (c: FieldCtx) => string | undefined;
}): IssuanceField {
  return d as unknown as IssuanceField;
}

export const KEY_TYPES: SegmentOption<KeyType>[] = [
  { value: 'ec256', label: 'EC P-256' },
  { value: 'ec384', label: 'EC P-384' },
  { value: 'rsa2048', label: 'RSA 2048' },
  { value: 'rsa3072', label: 'RSA 3072' },
  { value: 'rsa4096', label: 'RSA 4096' },
];

function boolEditor(label: string, on: string, off: string) {
  return (v: boolean, set: (v: boolean) => void) => (
    <span className="flex items-center gap-2">
      <Switch aria-label={label} checked={v} onCheckedChange={set} />
      <span className="text-sm text-ink-muted">{v ? on : off}</span>
    </span>
  );
}

// Adaptation (preflight A9): `RenewPolicy.value` in percent mode is the
// share of the lifetime REMAINING when renewal fires (internal/issuance/
// policy.go's NextRenewAt: notAfter - life/100*value), not elapsed — the
// built-in default (BuiltinDefaults()) is 33, not a majority-elapsed value,
// and the copy below says "remains", matching RenewPolicy.mode's own
// description in api/openapi.yaml.
export const ISSUANCE_FIELDS: IssuanceField[] = [
  def({
    key: 'caId',
    label: 'Certificate authority',
    help: 'defaults.caId',
    initial: (c) => c.cas[0]?.id ?? '',
    display: (v, c) => c.cas.find((x) => x.id === v)?.name ?? <span className="font-mono text-xs">{v}</span>,
    // Combobox's own clear button calls onChange(undefined); mapped to
    // null (review fix round 1, #4) so it resets to inherited instead of
    // setting an empty string the API always 422s.
    editor: (v, set, c, id) => (
      <div className="w-full max-w-96">
        <Combobox
          id={id}
          aria-label="Certificate authority"
          value={v}
          onChange={(x) => set(x ?? null)}
          options={c.cas.map((x) => ({ value: x.id, label: x.name, hint: KIND_LABEL[x.type] }))}
          placeholder="Choose CA"
          emptyText="No CAs yet"
        />
      </div>
    ),
    disabledReason: (c) => (c.cas.length === 0 ? 'No CAs yet' : undefined),
  }),
  def({
    key: 'accountId',
    label: 'ACME account',
    help: 'defaults.accountId',
    initial: (c) => c.accounts[0]?.id ?? '',
    display: (v, c) => <span className="font-mono text-xs">{c.accounts.find((a) => a.id === v)?.email ?? v}</span>,
    editor: (v, set, c, id) => (
      <div className="w-full max-w-96">
        <Combobox
          id={id}
          aria-label="ACME account"
          mono
          value={v}
          onChange={(x) => set(x ?? null)}
          options={c.accounts.map((a) => ({ value: a.id, label: a.email, hint: c.cas.find((x) => x.id === a.caId)?.name }))}
          placeholder="Choose account"
          emptyText="No accounts yet"
        />
      </div>
    ),
    disabledReason: (c) => (c.accounts.length === 0 ? 'No accounts yet' : undefined),
  }),
  def({
    key: 'keyType',
    label: 'Key type',
    help: 'defaults.keyType',
    initial: () => 'ec256',
    display: (v) => KEY_TYPES.find((k) => k.value === v)?.label ?? v,
    editor: (v, set) => <SegmentedControl<KeyType> aria-label="Key type" value={v} onChange={set} options={KEY_TYPES} />,
  }),
  def({
    key: 'renewPolicy',
    label: 'Renewal',
    help: 'defaults.renewPolicy',
    initial: () => ({ mode: 'percent', value: 33, useAri: false }),
    display: (v) => `${v.mode === 'days' ? `${v.value} days before expiry` : `When ${v.value}% of the lifetime remains`}${v.useAri ? ', ARI on' : ''}`,
    editor: (v, set, _c, id) => (
      <div className="flex flex-wrap items-center gap-3">
        <SegmentedControl
          aria-label="Renewal mode"
          value={v.mode}
          onChange={(mode) => set({ ...v, mode, value: mode === 'days' ? 30 : 33 })}
          options={[
            { value: 'days', label: 'Days' },
            { value: 'percent', label: 'Percent' },
          ]}
        />
        <Input
          id={id}
          type="number"
          min={1}
          max={v.mode === 'days' ? 365 : 99}
          className="w-24"
          aria-label={v.mode === 'days' ? 'Days before expiry' : 'Percent of lifetime remaining'}
          value={v.value}
          onChange={(e) => set({ ...v, value: Number(e.target.value) })}
        />
        <div className="w-full max-w-96">
          <SwitchField id={`${id}-ari`} label="ARI" help="defaults.useAri" checked={v.useAri} onCheckedChange={(useAri) => set({ ...v, useAri })} onText="Use renewal info" offText="Ignore renewal info" />
        </div>
      </div>
    ),
  }),
  def({
    key: 'preferredChain',
    label: 'Preferred chain',
    help: 'defaults.preferredChain',
    initial: () => '',
    display: (v) => (v ? <span className="font-mono text-xs">{v}</span> : 'CA default'),
    editor: (v, set, _c, id) => <Input id={id} className="w-full max-w-96 font-mono text-xs" value={v} onChange={(e) => set(e.target.value)} placeholder="ISRG Root X1" />,
  }),
  def({
    key: 'reuseKey',
    label: 'Reuse key',
    help: 'defaults.reuseKey',
    initial: () => false,
    display: (v) => (v ? 'Keep key' : 'New key each renewal'),
    editor: boolEditor('Reuse key', 'Keep key', 'New key each renewal'),
  }),
  def({
    key: 'mustStaple',
    label: 'Must-Staple',
    help: 'defaults.mustStaple',
    initial: () => false,
    display: (v) => (v ? 'On' : 'Off'),
    editor: boolEditor('Must-Staple', 'On', 'Off'),
  }),
  def({
    key: 'propagationSeconds',
    label: 'Propagation wait',
    help: 'defaults.propagationSeconds',
    initial: () => 120,
    display: (v) => `${v} s`,
    editor: (v, set, _c, id) => (
      <span className="flex items-center gap-2">
        <Input id={id} type="number" min={0} max={3600} className="w-24" aria-label="Propagation wait in seconds" value={v} onChange={(e) => set(Number(e.target.value))} />
        <span className="text-ink-muted">s</span>
      </span>
    ),
  }),
  def({
    key: 'resolvers',
    label: 'Resolvers',
    help: 'defaults.resolvers',
    initial: () => [],
    display: (v) => (v.length ? <span className="font-mono text-xs">{v.join(', ')}</span> : 'System resolvers'),
    editor: (v, set, _c, id) => (
      <div className="w-full max-w-96">
        <ListInput id={id} aria-label="Resolvers" value={v} onChange={set} placeholder="1.1.1.1:53" />
      </div>
    ),
  }),
  def({
    key: 'verificationRules',
    label: 'Verification rules',
    help: 'rules.catchAll',
    initial: (c) => [{ match: '*', method: 'dns-01', dnsCredentialId: c.credentials[0]?.id }],
    display: (v, c) => rulesSummary(v, c.credentials, c.clients),
    editor: (v, set, c) => (
      <div className="w-full">
        <VerificationRulesEditor rules={v} onChange={set} credentials={c.credentials} clients={c.clients} agentModes={c.agentModes} />
      </div>
    ),
  }),
];

export function rulesSummary(rules: VerificationRule[], creds: DnsCredential[], clients: Client[]): string {
  if (!rules.length) return 'None';
  return rules.map((r) => `${r.match} → ${ruleTarget(r, creds, clients)}`).join('; ');
}

// enabled: !!orgId guards the no-org edge case (IssuanceDefaultsSection
// still calls this hook unconditionally, with orgId '', before its own
// early return) so it doesn't fire requests against a malformed /orgs//...
// path.
export function useFieldCtx(orgId: string): FieldCtx {
  const cas = useQuery({ ...casQuery(orgId), enabled: !!orgId }).data ?? [];
  const accounts = useQuery({ ...accountsQuery(orgId), enabled: !!orgId }).data ?? [];
  const credentials = useQuery({ ...dnsCredentialsQuery(orgId), enabled: !!orgId }).data ?? [];
  const clients = useQuery({ ...allClientsQuery(orgId), enabled: !!orgId }).data?.items ?? [];
  return { cas, accounts, credentials, clients };
}

export const fromDefault = (): EffectiveValue => ({ value: null, source: 'default' });

// Review fix round 1 (#1): the Global tab's "not overridden" fields always
// show source 'default' (Global has no level above it to ask) but with the
// server's built-in value for display, not a bare null — `builtin` is
// `GET /settings/issuance_defaults`'s `value` (default-filled), never
// `stored` (the raw saved object, which is what decides whether a field
// counts as overridden at all — see IssuanceDefaultsSection).
export function fromBuiltin(builtin: IssuanceDefaults) {
  return (k: FieldKey): EffectiveValue => ({ value: builtin[k] ?? null, source: 'default' }) as EffectiveValue;
}

// Adaptation (preflight A8): the source of truth for the Org tab's badge —
// GET .../issuance-defaults/effective already resolves cert > org > global >
// built-in and names the level, so this is a plain lookup, never a
// raw-value comparison.
export function fromEffective(eff: EffectiveMap) {
  return (k: FieldKey): EffectiveValue => (eff[k] as EffectiveValue | undefined) ?? fromDefault();
}

export function chainFor(global: IssuanceDefaults, org: IssuanceDefaults | undefined, ctx: FieldCtx) {
  return (k: FieldKey): ChainEntry[] => {
    const f = ISSUANCE_FIELDS.find((x) => x.key === k);
    const show = (v: unknown): ReactNode => (v == null ? 'server default' : f ? f.display(v, ctx) : String(v));
    const out: ChainEntry[] = [{ level: 'Global', value: show(global[k]) }];
    if (org) out.push({ level: 'Org', value: org[k] == null ? 'inherits' : show(org[k]) });
    return out;
  };
}

// Review fix round 1 (#1, #3): a PUT to either issuance-defaults endpoint
// fully replaces the section, so every field this form renders is sent
// explicitly — a real value for an overridden field, or `null` (the API's
// own "unset" spelling) for one that isn't, never an omitted key. This is
// what makes "Reset to inherited" round-trip cleanly ({x: null, <sibling
// kept>}) and stops an untouched field from silently riding along as a
// concrete value just because the draft object happened to carry it.
//
// Review fix round 2: `value` is spread first, so a key this page doesn't
// render (today only `verificationRules`, which Task 13 adds a UI for; the
// same holds for anything added later) passes through untouched instead of
// being dropped — a "replace the whole object" PUT would otherwise delete
// it on any unrelated save, Global or Org.
export function fullPayload(value: IssuanceDefaults): IssuanceDefaults {
  return { ...value, ...Object.fromEntries(ISSUANCE_FIELDS.map((f) => [f.key, value[f.key] ?? null])) } as IssuanceDefaults;
}

// A 422's title is "Invalid <field>" or "Invalid <field>.<sub>" (mapErr /
// unprocessable in internal/api), so this is an exact lookup against the
// field keys this form actually renders — no prose keyword-matching needed.
export function fieldFromTitle(title: string): FieldKey | null {
  const name = title.replace(/^Invalid\s+/, '').split('.')[0];
  return ISSUANCE_FIELDS.some((f) => f.key === name) ? (name as FieldKey) : null;
}

export type FormProps = {
  value: IssuanceDefaults;
  onChange: (v: IssuanceDefaults) => void;
  inherited: (k: FieldKey) => EffectiveValue;
  chain?: (k: FieldKey) => ChainEntry[];
  ctx: FieldCtx;
  exclude?: FieldKey[];
  error?: (k: FieldKey) => string | null | undefined;
  /** True while a field was reset to inherited this session but the save hasn't landed (review fix round 1, #3). */
  pending?: (k: FieldKey) => boolean;
};

// Task 4 (R12 deviation): the effective CA (this form's own `caId` override,
// else whatever the inherited chain resolves to) is computed here, from the
// form's own props, so the account field's disabled-with-tooltip state
// works the same wherever this form is used (the wizard's Options step,
// Settings' Org/Global issuance defaults) with no extra plumbing from the
// caller.
function effectiveCa(value: IssuanceDefaults, inherited: FormProps['inherited'], cas: FieldCtx['cas']) {
  const id = value.caId ?? (inherited('caId').value as string | null | undefined) ?? undefined;
  return cas.find((c) => c.id === id);
}

export function IssuanceDefaultsForm({ value, onChange, inherited, chain, ctx, exclude = [], error, pending }: FormProps) {
  const eca = effectiveCa(value, inherited, ctx.cas);
  const privateCa = !!eca && isPrivate(eca);
  // Batch 2 review (Minor): the onChange interception above only fires when
  // the user actually touches caId — it never runs for a certificate that
  // loads (e.g. the wizard's edit route) already carrying an accountId
  // override with no caId override of its own, whose *inherited* default
  // CA already happens to be private (set by org/global defaults, or by
  // this same certificate's caId override having been removed in an
  // earlier session). Reconcile that stale combination as soon as it's
  // seen, so an unrelated Save doesn't 422 with "account belongs to a
  // different CA".
  useEffect(() => {
    if (privateCa && value.accountId != null) onChange({ ...value, accountId: null });
    // Only re-run when the reconciled condition itself changes; onChange
    // and value are covered indirectly (a clear changes value.accountId to
    // null, which flips the condition straight back to false).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [privateCa, value.accountId]);
  return (
    <div className="grid">
      {ISSUANCE_FIELDS.filter((f) => !exclude.includes(f.key)).map((f) => {
        const id = `f-${f.key}`;
        const accountPrivate = f.key === 'accountId' && privateCa;
        return (
          <InheritableField<unknown>
            key={f.key}
            id={id}
            label={f.label}
            help={accountPrivate ? 'defaults.accountPrivate' : f.help}
            value={value[f.key] as unknown}
            // EffectiveValue is a union across each field's own Effective*
            // shape (EffectiveUuid | EffectiveString | ...); TS widens their
            // merged 'value' key to optional, but every variant always
            // carries it (see api/openapi.yaml's Effective* schemas, all
            // `required: [value, source]`) — this cast only relaxes that,
            // it doesn't change what's passed.
            inherited={inherited(f.key) as { value: unknown; source: Source }}
            chain={chain?.(f.key)}
            initial={f.initial(ctx)}
            display={(v) => f.display(v, ctx)}
            editor={(v, set) => f.editor(v, set, ctx, id)}
            onChange={(v) => {
              const next = { ...value, [f.key]: v } as IssuanceDefaults;
              // Choosing a private CA (or resetting the override back to an
              // inherited private one) makes an accountId override
              // meaningless — ACME accounts never apply to a private CA,
              // and the API 422s a cert-level account override once its
              // effective CA is private — so clear it in the same update.
              if (f.key === 'caId') {
                const nextCa = effectiveCa(next, inherited, ctx.cas);
                if (nextCa && isPrivate(nextCa) && next.accountId != null) next.accountId = null;
              }
              onChange(next);
            }}
            error={error?.(f.key)}
            overrideDisabled={accountPrivate ? 'Not used by private CAs' : f.disabledReason?.(ctx)}
            pending={pending?.(f.key)}
          />
        );
      })}
    </div>
  );
}
