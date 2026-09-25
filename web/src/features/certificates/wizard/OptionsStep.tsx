import type { Dispatch } from 'react';
import { useQuery } from '@tanstack/react-query';
import { effectiveDefaultsQuery, orgDefaultsQuery } from '@/api/queries/defaults';
import { settingsQuery } from '@/api/queries/settings';
import type { IssuanceDefaults } from '@/api/types';
import { chainFor, fromEffective, IssuanceDefaultsForm, useFieldCtx } from '@/features/settings/issuanceFields';
import type { WizardAction, WizardState } from './state';

export function OptionsStep({ orgId, state, dispatch }: { orgId: string; state: WizardState; dispatch: Dispatch<WizardAction> }) {
  const ctx = useFieldCtx(orgId);
  const eff = useQuery(effectiveDefaultsQuery(orgId)).data ?? {};
  // I3 (Important, Task 10 ruling): chainFor's "Global" row must come from
  // `stored` (the raw saved section, null for a field never actually set at
  // Global), not `value` (built-in-filled for display everywhere else) — a
  // field whose badge reads "Default" would otherwise claim an inherited
  // "Global: EC P-256" it never actually got from Global.
  const global = (useQuery(settingsQuery('issuance_defaults')).data?.stored ?? {}) as IssuanceDefaults;
  const org = useQuery(orgDefaultsQuery(orgId)).data;
  return (
    <IssuanceDefaultsForm
      value={state.overrides}
      onChange={(overrides) => dispatch({ type: 'setOverrides', overrides })}
      inherited={fromEffective(eff)}
      chain={chainFor(global, org, ctx)}
      ctx={ctx}
      exclude={['verificationRules']}
    />
  );
}
