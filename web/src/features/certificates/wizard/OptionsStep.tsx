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
  const global = (useQuery(settingsQuery('issuance_defaults')).data?.value ?? {}) as IssuanceDefaults;
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
