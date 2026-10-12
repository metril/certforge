import type { AdcsProbeRequest, AdcsProbeTemplate, CA, CAInput, CAPreset, CaType } from '@/api/types';
import { UNCHANGED } from '@/api/types';

const CUSTOM = 'custom';

/** The acme kind's own draft — everything the pre-5B CaSheet form held,
 * minus `name` (task 2: name is shared by every kind, hoisted to CaDraft). */
export type AcmeDraft = {
  preset: CAInput['preset'] | '';
  directoryUrl: string;
  trustBundlePem: string;
  eabKid: string;
  eabHmac: string | undefined;
  resolvers: string[];
};

/** `config` mirrors `signers[localca]`'s formData (task-2-brief "Kind
 * state"); `importing` is UI-only (the Import existing CA switch) and never
 * sent itself — it decides which of config's fields `toCaInput` keeps. */
export type LocalCaDraft = { config: Record<string, unknown>; importing: boolean };
export type VaultPkiDraft = { config: Record<string, unknown> };
export type AdcsDraft = { config: Record<string, unknown> };

/** Switching the Type control keeps each kind's own draft (task-2-brief:
 * "Switching kind keeps each body's draft"), so every kind's draft lives in
 * this one object at once. */
export type CaDraft = { kind: CaType; name: string; acme: AcmeDraft; localca: LocalCaDraft; vaultpki: VaultPkiDraft; adcs: AdcsDraft };

export const emptyAcme: AcmeDraft = { preset: '', directoryUrl: '', trustBundlePem: '', eabKid: '', eabHmac: undefined, resolvers: [] };
export const emptyLocalCa: LocalCaDraft = { config: {}, importing: false };
export const emptyVaultPki: VaultPkiDraft = { config: {} };
export const emptyAdcs: AdcsDraft = { config: {} };

function acmeFromCa(ca: CA): AcmeDraft {
  return {
    preset: ca.preset ?? '',
    directoryUrl: ca.directoryUrl,
    trustBundlePem: ca.trustBundlePem ?? '',
    eabKid: ca.eabKid ?? '',
    // Adaptation (preflight A18, carried from the pre-5B CaSheet): the API's
    // source of truth for "a stored EAB HMAC exists" is CA.hasEab, not the
    // presence of eabKid (a CA can have a kid without ever having set an HMAC).
    eabHmac: ca.hasEab ? UNCHANGED : undefined,
    resolvers: ca.resolvers ?? [],
  };
}

// Batch 1 review (Important): `CA.config` carries these read-only fields
// alongside LocalCaConfig's own schema properties (subject, keyType, ...).
// The signers[localca] schema has `additionalProperties: false`, so seeding
// the edit draft with the full `ca.config` makes SchemaForm's Ajv `validate()`
// fail outright on Save (a silent no-op) the moment the operator opens an
// existing localca CA to edit it.
const LOCALCA_READONLY_KEYS = ['imported', 'issuingPem', 'retired', 'revokedCount'];

// AdcsConfig's templateOid and templateKeyTypes are read-only (set from the policy) and the
// signers[adcs] schema has additionalProperties: false, so the edit draft
// drops it; the stored password is seeded with the unchanged sentinel.
function adcsConfigFromCa(config: Record<string, unknown>): Record<string, unknown> {
  const rest: Record<string, unknown> = { ...config };
  delete rest.templateOid;
  delete rest.templateKeyTypes;
  return { ...rest, password: UNCHANGED };
}

function localCaConfigFromCa(config: Record<string, unknown>): Record<string, unknown> {
  const c = { ...config };
  for (const k of LOCALCA_READONLY_KEYS) delete c[k];
  return c;
}

/** Builds a fresh draft: every kind starts blank except the one the CA
 * already is (editing) or `initialKind` names (create, from `?kind=`). */
export function initialDraft(ca: CA | undefined, initialKind: CaType): CaDraft {
  if (!ca) return { kind: initialKind, name: '', acme: emptyAcme, localca: emptyLocalCa, vaultpki: emptyVaultPki, adcs: emptyAdcs };
  return {
    kind: ca.type,
    name: ca.name,
    acme: ca.type === 'acme' ? acmeFromCa(ca) : emptyAcme,
    // Editing never shows the Import switch (create-only, task-2-brief), so
    // `importing` starts false regardless of whether this CA was imported.
    localca: ca.type === 'localca' ? { config: localCaConfigFromCa(ca.config as Record<string, unknown>), importing: false } : emptyLocalCa,
    vaultpki: ca.type === 'vaultpki' ? { config: ca.config } : emptyVaultPki,
    adcs: ca.type === 'adcs' ? { config: adcsConfigFromCa(ca.config as Record<string, unknown>) } : emptyAdcs,
  };
}

/** localca's `config` for the request body: on edit only `maxLeafDays`/`crl`
 * are mutable (task-2-brief; pre-flight ruling: no stored-key sentinel is
 * ever sent), so the immutable fields are dropped outright rather than
 * echoed back. On create, `importing` decides which half of the schema's
 * fields apply — generated-root fields or import fields, never both. */
function localCaConfig(d: LocalCaDraft, editing: boolean): Record<string, unknown> {
  const c = d.config as {
    subject?: unknown;
    keyType?: unknown;
    rootValidityYears?: unknown;
    issuingValidityYears?: unknown;
    maxLeafDays?: unknown;
    crl?: unknown;
    importPem?: unknown;
    importKeyPem?: unknown;
  };
  if (editing) return { maxLeafDays: c.maxLeafDays, crl: c.crl };
  if (d.importing) return { maxLeafDays: c.maxLeafDays, crl: c.crl, importPem: c.importPem, importKeyPem: c.importKeyPem };
  return { subject: c.subject, keyType: c.keyType, rootValidityYears: c.rootValidityYears, issuingValidityYears: c.issuingValidityYears, maxLeafDays: c.maxLeafDays, crl: c.crl };
}

/** Builds the CAInput body for whichever kind the draft is currently on.
 * `presets` resolves the acme body's EAB visibility (custom, or a preset
 * that `requiresEab`) the same way the pre-5B CaSheet's own `submit()` did;
 * `ca` is the CA being edited, if any (governs both the acme EAB-removal
 * case and localca's immutable-field dropping above). */
export function toCaInput(draft: CaDraft, ctx: { presets: CAPreset[]; ca?: CA }): CAInput {
  const name = draft.name.trim();
  if (draft.kind === 'acme') {
    const a = draft.acme;
    const preset = ctx.presets.find((p) => p.preset === a.preset);
    const custom = a.preset === CUSTOM;
    const showEab = custom || !!preset?.requiresEab;
    const kid = a.eabKid.trim();
    return {
      name,
      type: 'acme',
      preset: a.preset || undefined,
      directoryUrl: a.directoryUrl.trim(),
      trustBundlePem: custom && a.trustBundlePem.trim() ? a.trustBundlePem.trim() : undefined,
      eabKid: showEab && kid ? kid : undefined,
      eabHmac: showEab ? (kid ? a.eabHmac : ctx.ca?.hasEab ? '' : undefined) : undefined,
      resolvers: a.resolvers,
    };
  }
  if (draft.kind === 'adcs') {
    // An emptied password on edit means "keep the stored one": leave it out.
    const { password, ...rest } = draft.adcs.config;
    return { name, type: 'adcs', config: password === '' || password === undefined ? rest : { ...rest, password } };
  }
  const config = draft.kind === 'localca' ? localCaConfig(draft.localca, !!ctx.ca) : draft.vaultpki.config;
  return { name, type: draft.kind, config };
}

const str = (v: unknown) => (typeof v === 'string' ? v.trim() : '');

/** Builds an AD CS probe body from an adcs config (a draft or a saved CA's).
 * With `caId`, an untouched password (the sentinel or empty) reuses the saved
 * CA's. Returns null until the policy URL, username and a password are set. */
export function adcsProbeRequest(config: Record<string, unknown>, caId?: string): AdcsProbeRequest | null {
  const cepUrl = str(config.cepUrl);
  const username = str(config.username);
  const raw = typeof config.password === 'string' ? config.password : '';
  const keep = !!caId && (raw === '' || raw === UNCHANGED);
  if (!cepUrl || !username || (!raw && !keep)) return null;
  const req: AdcsProbeRequest = { cepUrl, username, password: keep ? UNCHANGED : raw };
  if (keep) req.caId = caId;
  if (str(config.cesUrl)) req.cesUrl = str(config.cesUrl);
  if (str(config.caBundlePem)) req.caBundlePem = str(config.caBundlePem);
  if (str(config.template)) req.template = str(config.template);
  if (typeof config.timeoutSeconds === 'number') req.timeoutSeconds = config.timeoutSeconds;
  return req;
}

export const ADCS_PROBE_BLOCKED = 'Fill in the policy URL, username and password first.';

/** Why a published template cannot back this CA, or null when it can. */
export function adcsTemplateReason(t: AdcsProbeTemplate): string | null {
  if (!t.canEnroll) return 'The service account cannot enroll on this template.';
  if (t.requiresApproval) return 'Requests need CA manager approval; only automatic issuance works.';
  return null;
}
