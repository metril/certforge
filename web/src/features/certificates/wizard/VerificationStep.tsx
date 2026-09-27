import { useEffect, useMemo, useState, type Dispatch } from 'react';
import { useQuery } from '@tanstack/react-query';
import { allCertificatesQuery } from '@/api/queries/certificates';
import { allClientsQuery } from '@/api/queries/clients';
import { dnsCredentialsQuery, metaSchemasQuery } from '@/api/queries/dns';
import type { ProviderSchema } from '@/api/types';
import { CredentialSheet } from '@/features/issuers/CredentialSheet';
import { CoveragePanel } from '@/forms/CoveragePanel';
import { ProviderPicker } from '@/forms/ProviderPicker';
import { VerificationRulesEditor } from '@/forms/VerificationRulesEditor';
import { coverage, prefillRules, type Inherited } from '@/lib/coverage';
import { makeSuggester } from '@/lib/lastCredential';
import type { WizardAction, WizardState } from './state';

type Props = { orgId: string; state: WizardState; dispatch: Dispatch<WizardAction>; inherited: Inherited };

export function VerificationStep({ orgId, state, dispatch, inherited }: Props) {
  const credsQ = useQuery(dnsCredentialsQuery(orgId));
  const certsQ = useQuery(allCertificatesQuery(orgId));
  const clientsQ = useQuery(allClientsQuery(orgId));
  const { data: meta } = useQuery(metaSchemasQuery);
  const creds = useMemo(() => credsQ.data ?? [], [credsQ.data]);
  const clients = useMemo(() => clientsQ.data?.items ?? [], [clientsQ.data]);
  const [pickerFor, setPickerFor] = useState<number | null>(null);
  const [sheet, setSheet] = useState<{ provider: ProviderSchema; ruleIndex: number } | null>(null);

  // Until the user edits the rules, keep them prefilled from the names (one dns-01 rule per zone).
  useEffect(() => {
    if (state.rulesTouched || !credsQ.isSuccess || !certsQ.isSuccess) return;
    const rules = prefillRules(state.names, makeSuggester(certsQ.data, creds), inherited, clients);
    if (JSON.stringify(rules) !== JSON.stringify(state.rules)) dispatch({ type: 'prefillRules', rules });
  }, [state.rulesTouched, state.names, state.rules, credsQ.isSuccess, certsQ.isSuccess, certsQ.data, creds, inherited, clients, dispatch]);

  // Fix round 1 (review): remembering a rule's credential per zone happens
  // once, after a certificate is actually created (Task 14, via
  // `rememberFromRules`) — not here on every keystroke, which would write a
  // junk localStorage key per character typed into the match field.
  const setCredential = (i: number, id: string) =>
    dispatch({ type: 'setRules', rules: state.rules.map((r, j) => (j === i ? { ...r, dnsCredentialId: id } : r)) });

  return (
    <div className="grid gap-6">
      <VerificationRulesEditor
        rules={state.rules}
        onChange={(rules) => dispatch({ type: 'setRules', rules })}
        credentials={creds}
        clients={clients}
        onAddCredential={setPickerFor}
      />
      <CoveragePanel items={coverage(state.names, state.rules, inherited, clients)} credentials={creds} clients={clients} />
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
