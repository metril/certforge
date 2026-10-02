import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert, CircleCheck } from 'lucide-react';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { IssuanceDefaults } from '@/api/types';
import { ISSUANCE_FIELDS, useFieldCtx } from '@/features/settings/issuanceFields';
import { coverage, isCovered, type Inherited } from '@/lib/coverage';
import { classifyName } from '@/lib/names';
import { METHOD_LABEL } from '@/lib/rules';
import { effectiveOf } from './ReviewStep';
import type { WizardState } from './state';

/** "DNS + HTTP, 3 rules": the unique method labels among the rules, in the
 * order they first appear, then the rule count. */
function ruleSummary(rules: WizardState['rules']): string {
  const labels: string[] = [];
  for (const r of rules) if (!labels.includes(METHOD_LABEL[r.method])) labels.push(METHOD_LABEL[r.method]);
  const count = `${rules.length} ${rules.length === 1 ? 'rule' : 'rules'}`;
  return labels.length ? `${labels.join(' + ')}, ${count}` : count;
}

export function SummaryRail({ orgId, state, inherited, privateCa }: { orgId: string; state: WizardState; inherited: Inherited; privateCa: boolean }) {
  const ctx = useFieldCtx(orgId);
  const eff = useQuery(effectiveDefaultsQuery(orgId)).data ?? {};
  const cov = coverage(state.names, state.rules, inherited, ctx.clients);
  const covered = cov.filter(isCovered).length;
  const zones = new Set(state.names.map((n) => classifyName(n).zone).filter(Boolean)).size;
  const show = (k: keyof IssuanceDefaults) => {
    const f = ISSUANCE_FIELDS.find((x) => x.key === k)!;
    const e = effectiveOf(state.overrides, eff, k);
    return e.value === null || e.value === undefined ? 'Built-in' : f.display(e.value, ctx);
  };
  const rows: [string, ReactNode][] = [
    ['Names', `${state.names.length} in ${zones} ${zones === 1 ? 'zone' : 'zones'}`],
    ['Common name', <span className="break-all font-mono text-xs">{state.cn ?? '–'}</span>],
    // Task 4 (R12 deviation): a private effective CA needs no verification.
    ['Verification', privateCa ? 'Not needed' : ruleSummary(state.rules)],
    [
      'Coverage',
      // Batch 2 review (Important, controller ruling): a private effective
      // CA needs no coverage at all — "Not needed", neutral, no alert
      // icon — not a "0 of N names" warning for something that was never
      // required.
      privateCa ? (
        'Not needed'
      ) : (
        <span className="inline-flex items-center gap-1">
          {cov.length > 0 && covered === cov.length ? (
            <CircleCheck className="size-4 text-valid" aria-hidden />
          ) : (
            <CircleAlert className="size-4 text-expiring" aria-hidden />
          )}
          {covered} of {cov.length} names
        </span>
      ),
    ],
    ['CA', show('caId')],
    ['Key type', show('keyType')],
    ['Renewal', show('renewPolicy')],
  ];
  return (
    <aside aria-label="Summary" className="h-fit border-border text-sm md:sticky md:top-6 md:border-l md:pl-6">
      <dl className="grid gap-3">
        {rows.map(([label, value]) => (
          <div key={label} className="grid gap-0.5">
            <dt className="text-xs text-ink-muted">{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </aside>
  );
}
