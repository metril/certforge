import type { Certificate, CertificateInput, IssuanceDefaults, VerificationMethod, VerificationRule } from '@/api/types';
import { classifyName, MAX_NAMES } from '@/lib/names';

export type WizardState = {
  names: string[];
  cn: string | null;
  name: string;
  nameTouched: boolean;
  method: VerificationMethod;
  rules: VerificationRule[];
  rulesTouched: boolean;
  overrides: IssuanceDefaults;
};

export type WizardAction =
  | { type: 'addNames'; names: string[] }
  | { type: 'removeName'; name: string }
  | { type: 'setCn'; name: string }
  | { type: 'setName'; name: string }
  | { type: 'setMethod'; method: VerificationMethod }
  | { type: 'setRules'; rules: VerificationRule[] }
  | { type: 'prefillRules'; rules: VerificationRule[] }
  | { type: 'setOverrides'; overrides: IssuanceDefaults };

export const initialWizard: WizardState = {
  names: [],
  cn: null,
  name: '',
  nameTouched: false,
  method: 'dns-01',
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
    case 'setMethod':
      return {
        ...s,
        method: a.method,
        rulesTouched: true,
        rules: s.rules.map((rule) => (a.method === 'manual-dns' ? { match: rule.match, method: a.method } : { ...rule, method: a.method })),
      };
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

export function toCertificateInput(s: WizardState): CertificateInput {
  return { name: s.name.trim() || (s.cn ?? ''), commonName: s.cn ?? '', sans: s.names, verificationRules: s.rules, overrides: s.overrides };
}

export function fromCertificate(c: Certificate): WizardState {
  const names = c.sans.includes(c.commonName) ? c.sans : [c.commonName, ...c.sans];
  return {
    names,
    cn: c.commonName,
    name: c.name,
    nameTouched: true,
    method: c.verificationRules[0]?.method ?? 'dns-01',
    rules: c.verificationRules,
    rulesTouched: true,
    overrides: c.overrides ?? {},
  };
}
