import type { Certificate, CertificateInput, EffectiveMap, IssuanceDefaults, VerificationRule } from '@/api/types';
import { classifyName, MAX_NAMES } from '@/lib/names';

export type WizardState = {
  names: string[];
  cn: string | null;
  name: string;
  nameTouched: boolean;
  rules: VerificationRule[];
  rulesTouched: boolean;
  overrides: IssuanceDefaults;
};

export type WizardAction =
  | { type: 'addNames'; names: string[] }
  | { type: 'removeName'; name: string }
  | { type: 'setCn'; name: string }
  | { type: 'setName'; name: string }
  | { type: 'setRules'; rules: VerificationRule[] }
  | { type: 'prefillRules'; rules: VerificationRule[] }
  | { type: 'setOverrides'; overrides: IssuanceDefaults };

export const initialWizard: WizardState = {
  names: [],
  cn: null,
  name: '',
  nameTouched: false,
  rules: [],
  rulesTouched: false,
  overrides: {},
};

const withCn = (s: WizardState, cn: string | null): WizardState => ({ ...s, cn, name: s.nameTouched ? s.name : (cn ?? '') });

export function wizardReducer(s: WizardState, a: WizardAction): WizardState {
  switch (a.type) {
    case 'addNames': {
      const names = [...s.names];
      for (const n of a.names) if (!names.includes(n)) names.push(n);
      return withCn({ ...s, names }, s.cn ?? names.find((n) => classifyName(n).kind !== 'invalid') ?? null);
    }
    case 'removeName': {
      const names = s.names.filter((n) => n !== a.name);
      const cn = s.cn === a.name ? (names.find((n) => classifyName(n).kind !== 'invalid') ?? null) : s.cn;
      return withCn({ ...s, names }, cn);
    }
    case 'setCn':
      return withCn(s, a.name);
    case 'setName':
      return { ...s, name: a.name, nameTouched: true };
    case 'setRules':
      return { ...s, rules: a.rules, rulesTouched: true };
    case 'prefillRules':
      return { ...s, rules: a.rules };
    case 'setOverrides':
      return { ...s, overrides: a.overrides };
  }
}

export function canContinueNames(s: WizardState): boolean {
  return s.names.length > 0 && s.names.length <= MAX_NAMES && !!s.cn && s.names.every((n) => classifyName(n).kind !== 'invalid');
}

// Task 4 (R12 deviation): the CA is picked in Options, after Verification,
// so the effective CA is the cert-level override if there is one, else
// whatever org/global defaults resolve to (EffectiveMap.caId.value).
export function effectiveCaId(s: { overrides: IssuanceDefaults }, eff: EffectiveMap): string | undefined {
  return s.overrides.caId ?? eff.caId?.value ?? undefined;
}

export function toCertificateInput(s: WizardState, opts: { privateCa?: boolean } = {}): CertificateInput {
  // A private effective CA needs no verification rules; rules the user
  // never touched (the auto-prefill from names, never a deliberate choice)
  // are sent as [] rather than whatever the prefill computed. A rule set
  // the user did touch (including on an edit's existing certificate) is
  // still sent as-is.
  const rules = opts.privateCa && !s.rulesTouched ? [] : s.rules;
  return { name: s.name.trim() || (s.cn ?? ''), commonName: s.cn ?? '', sans: s.names, verificationRules: rules, overrides: s.overrides };
}

export function fromCertificate(c: Certificate): WizardState {
  const names = c.sans.includes(c.commonName) ? c.sans : [c.commonName, ...c.sans];
  return {
    names,
    cn: c.commonName,
    name: c.name,
    nameTouched: true,
    rules: c.verificationRules,
    rulesTouched: true,
    overrides: c.overrides ?? {},
  };
}
