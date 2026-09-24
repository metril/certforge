import { useEffect, useMemo, useState, type Dispatch } from 'react';
import { useQuery } from '@tanstack/react-query';
import { allCertificatesQuery } from '@/api/queries/certificates';
import { dnsCredentialsQuery, metaSchemasQuery } from '@/api/queries/dns';
import type { ProviderSchema } from '@/api/types';
import { CredentialSheet } from '@/features/issuers/CredentialSheet';
import { CoveragePanel } from '@/forms/CoveragePanel';
import { ProviderPicker } from '@/forms/ProviderPicker';
import { VerificationRulesEditor } from '@/forms/VerificationRulesEditor';
import { coverage, prefillRules, type Inherited } from '@/lib/coverage';
import { makeSuggester, rememberCredentials } from '@/lib/lastCredential';
import type { WizardAction, WizardState } from './state';

type Props = { orgId: string; state: WizardState; dispatch: Dispatch<WizardAction>; inherited: Inherited };

export function VerificationStep({ orgId, state, dispatch, inherited }: Props) {
  const credsQ = useQuery(dnsCredentialsQuery(orgId));
  const certsQ = useQuery(allCertificatesQuery(orgId));
  const { data: meta } = useQuery(metaSchemasQuery);
  const creds = useMemo(() => credsQ.data ?? [], [credsQ.data]);
  const [pickerFor, setPickerFor] = useState<number | null>(null);
  const [sheet, setSheet] = useState<{ provider: ProviderSchema; ruleIndex: number } | null>(null);

  // Until the user edits the rules, keep them prefilled from the names (one per zone).
  useEffect(() => {
    if (state.rulesTouched || !credsQ.isSuccess || !certsQ.isSuccess) return;
    const rules = prefillRules(state.names, state.method, makeSuggester(certsQ.data, creds), inherited);
    if (JSON.stringify(rules) !== JSON.stringify(state.rules)) dispatch({ type: 'prefillRules', rules });
  }, [state.rulesTouched, state.names, state.method, state.rules, credsQ.isSuccess, certsQ.isSuccess, certsQ.data, creds, inherited, dispatch]);

  const setRules = (rules: typeof state.rules) => {
    dispatch({ type: 'setRules', rules });
    rememberCredentials(rules);
  };
  const setCredential = (i: number, id: string) => setRules(state.rules.map((r, j) => (j === i ? { ...r, dnsCredentialId: id } : r)));

  return (
    <div className="grid gap-6">
      <VerificationRulesEditor
        rules={state.rules}
        onChange={setRules}
        method={state.method}
        onMethodChange={(method) => dispatch({ type: 'setMethod', method })}
        credentials={creds}
        onAddCredential={setPickerFor}
      />
      <CoveragePanel items={coverage(state.names, state.rules, inherited)} credentials={creds} />
      <ProviderPicker
        open={pickerFor !== null}
        onOpenChange={(o) => !o && setPickerFor(null)}
        providers={meta?.dnsProviders ?? []}
        credentials={creds}
        onPickCredential={(c) => pickerFor !== null && setCredential(pickerFor, c.id)}
        onPickProvider={(p) => pickerFor !== null && setSheet({ provider: p, ruleIndex: pickerFor })}
      />
      {sheet && (
        <CredentialSheet
          key={sheet.provider.code}
          orgId={orgId}
          open
          provider={sheet.provider}
          onOpenChange={(o) => !o && setSheet(null)}
          onSaved={(c) => setCredential(sheet.ruleIndex, c.id)}
        />
      )}
    </div>
  );
}
