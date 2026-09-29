import { useEffect, useMemo, useState, type Dispatch, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleMinus } from 'lucide-react';
import { allCertificatesQuery } from '@/api/queries/certificates';
import { allClientsQuery } from '@/api/queries/clients';
import { dnsCredentialsQuery, metaSchemasQuery } from '@/api/queries/dns';
import type { ProviderSchema } from '@/api/types';
import { HelpTipBody } from '@/components/HelpTip';
import { SegmentedControl } from '@/components/SegmentedControl';
import { ToneChip } from '@/components/StatusChip';
import { Label } from '@/components/ui/label';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { CredentialSheet } from '@/features/issuers/CredentialSheet';
import { CoveragePanel } from '@/forms/CoveragePanel';
import { ProviderPicker } from '@/forms/ProviderPicker';
import { VerificationRulesEditor } from '@/forms/VerificationRulesEditor';
import { coverage, prefillRules, type Inherited } from '@/lib/coverage';
import { help } from '@/lib/help';
import { makeSuggester } from '@/lib/lastCredential';
import type { WizardAction, WizardState } from './state';

type Props = { orgId: string; state: WizardState; dispatch: Dispatch<WizardAction>; inherited: Inherited; privateCa: boolean };

/** Display-only "Needed"/"Not needed" segmented control (R12 deviation):
 * always disabled, follows `privateCa`, wrapped in a tooltip explaining why. */
function VerificationModeControl({ privateCa }: { privateCa: boolean }) {
  const helpKey = privateCa ? 'wizard.verificationNotNeeded' : 'wizard.verificationNeeded';
  return (
    <div className="flex items-center gap-1.5">
      <Label htmlFor="ver-mode">Verification</Label>
      <Tooltip>
        <TooltipTrigger asChild>
          <div tabIndex={0} className="inline-flex">
            <SegmentedControl
              id="ver-mode"
              aria-label="Verification"
              value={privateCa ? 'not-needed' : 'needed'}
              onChange={() => {}}
              options={[
                { value: 'needed', label: 'Needed', disabled: true },
                { value: 'not-needed', label: 'Not needed', disabled: true },
              ]}
            />
          </div>
        </TooltipTrigger>
        <TooltipContent>
          <HelpTipBody entry={help[helpKey]} />
        </TooltipContent>
      </Tooltip>
    </div>
  );
}

/** Wraps children with the dimmed/non-interactive treatment for a private
 * effective CA: `aria-disabled`, `pointer-events-none` (mouse) and `inert`
 * (batch 2 review, Minor: `pointer-events-none` alone still lets a
 * keyboard user tab into and edit the rules editor — `inert` removes it
 * from the tab order and blocks input entirely). `inert` is a plain DOM
 * attribute, not yet in this project's @types/react (18.3), so it's set
 * imperatively through a ref rather than as a JSX prop. */
function Dimmed({ active, children }: { active: boolean; children: ReactNode }) {
  return (
    <div
      ref={(el) => {
        if (!el) return;
        if (active) el.setAttribute('inert', '');
        else el.removeAttribute('inert');
      }}
      aria-disabled={active || undefined}
      className={active ? 'pointer-events-none opacity-50' : undefined}
    >
      {children}
    </div>
  );
}

/** Coverage panel's private-CA substitute: same per-name list, but every
 * row shows "Not needed" instead of a computed coverage state — nothing is
 * hidden, only the per-name description changes (R12 deviation). */
function NotNeededCoverage({ names }: { names: string[] }) {
  return (
    <section aria-label="Coverage" className="grid gap-2">
      <h3 className="text-sm font-semibold">Coverage</h3>
      <ul className="grid">
        {names.map((n) => (
          <li key={n} className="flex min-h-8 flex-wrap items-center gap-2 border-b border-border py-1 text-sm last:border-b-0">
            <span className="min-w-0 flex-1 truncate font-mono text-xs">{n}</span>
            <ToneChip tone="neutral" icon={CircleMinus} label="Not needed" />
          </li>
        ))}
      </ul>
    </section>
  );
}

export function VerificationStep({ orgId, state, dispatch, inherited, privateCa }: Props) {
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
      <VerificationModeControl privateCa={privateCa} />
      <Dimmed active={privateCa}>
        <VerificationRulesEditor
          rules={state.rules}
          onChange={(rules) => dispatch({ type: 'setRules', rules })}
          credentials={creds}
          clients={clients}
          onAddCredential={setPickerFor}
        />
      </Dimmed>
      <Dimmed active={privateCa}>
        {privateCa ? (
          <NotNeededCoverage names={state.names} />
        ) : (
          <CoveragePanel items={coverage(state.names, state.rules, inherited, clients)} credentials={creds} clients={clients} />
        )}
      </Dimmed>
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
