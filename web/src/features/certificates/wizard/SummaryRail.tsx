import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert, CircleCheck } from 'lucide-react';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { IssuanceDefaults } from '@/api/types';
import { ISSUANCE_FIELDS, useFieldCtx } from '@/features/settings/issuanceFields';
import { coverage, isCovered, type Inherited } from '@/lib/coverage';
import { classifyName } from '@/lib/names';
import { effectiveOf } from './ReviewStep';
import type { WizardState } from './state';

const METHOD: Record<string, string> = { 'dns-01': 'DNS-01', 'manual-dns': 'Manual DNS' };

export function SummaryRail({ orgId, state, inherited }: { orgId: string; state: WizardState; inherited: Inherited }) {
  const ctx = useFieldCtx(orgId);
  const eff = useQuery(effectiveDefaultsQuery(orgId)).data ?? {};
  const cov = coverage(state.names, state.rules, inherited);
  const covered = cov.filter(isCovered).length;
  const zones = new Set(state.names.map((n) => classifyName(n).zone).filter(Boolean)).size;
  const show = (k: keyof IssuanceDefaults) => {
    const f = ISSUANCE_FIELDS.find((x) => x.key === k)!;
    const e = effectiveOf(state.overrides, eff, k);
    return e.value === null || e.value === undefined ? 'Server default' : f.display(e.value, ctx);
  };
  const rows: [string, ReactNode][] = [
    ['Names', `${state.names.length} in ${zones} ${zones === 1 ? 'zone' : 'zones'}`],
    ['Common name', <span className="break-all font-mono text-xs">{state.cn ?? '–'}</span>],
    ['Verification', `${METHOD[state.method]}, ${state.rules.length} ${state.rules.length === 1 ? 'rule' : 'rules'}`],
    [
      'Coverage',
      <span className="inline-flex items-center gap-1">
        {cov.length > 0 && covered === cov.length ? (
          <CircleCheck className="size-4 text-valid" aria-hidden />
        ) : (
          <CircleAlert className="size-4 text-expiring" aria-hidden />
        )}
        {covered} of {cov.length} names
      </span>,
    ],
    ['CA', show('caId')],
    ['Key type', show('keyType')],
    ['Renewal', show('renewPolicy')],
  ];
  return (
    <aside aria-label="Summary" className="h-fit border-border text-sm lg:sticky lg:top-6 lg:border-l lg:pl-6">
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
