import type { Dispatch } from 'react';
import type { WizardAction, WizardState } from './state';
import { WizardIssuanceForm } from './WizardIssuanceForm';

export function OptionsStep({ orgId, state, dispatch }: { orgId: string; state: WizardState; dispatch: Dispatch<WizardAction> }) {
  return <WizardIssuanceForm orgId={orgId} state={state} dispatch={dispatch} exclude={['caId', 'verificationRules']} />;
}
