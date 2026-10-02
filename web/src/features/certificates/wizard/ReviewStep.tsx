import { Fragment, type Dispatch } from 'react';
import { useQuery } from '@tanstack/react-query';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { EffectiveValue, IssuanceDefaults } from '@/api/types';
import { Field } from '@/components/Field';
import { Input } from '@/components/ui/input';
import { effectiveText, isUnset, ISSUANCE_FIELDS, useFieldCtx, type FieldKey } from '@/features/settings/issuanceFields';
import { CoveragePanel } from '@/forms/CoveragePanel';
import { SourceBadge } from '@/forms/InheritableField';
import { coverage, type Inherited } from '@/lib/coverage';
import type { WizardAction, WizardState } from './state';

export function effectiveOf(overrides: IssuanceDefaults, eff: Partial<Record<FieldKey, EffectiveValue>>, k: FieldKey): EffectiveValue {
  const own = overrides[k];
  if (own !== null && own !== undefined) return { value: own, source: 'cert' } as EffectiveValue;
  return eff[k] ?? ({ value: null, source: 'default' } as EffectiveValue);
}

type Props = { orgId: string; state: WizardState; dispatch: Dispatch<WizardAction>; inherited: Inherited };

export function ReviewStep({ orgId, state, dispatch, inherited }: Props) {
  const ctx = useFieldCtx(orgId);
  const eff = useQuery(effectiveDefaultsQuery(orgId)).data ?? {};
  return (
    <div className="grid gap-8">
      <Field id="cert-name" label="Certificate name" className="max-w-md">
        <Input id="cert-name" value={state.name} onChange={(e) => dispatch({ type: 'setName', name: e.target.value })} />
      </Field>
      <section aria-labelledby="review-names" className="grid gap-2">
        <h3 id="review-names" className="text-sm font-semibold">
          Names
        </h3>
        <p className="break-all font-mono text-xs leading-relaxed">{state.names.join(', ')}</p>
      </section>
      <CoveragePanel items={coverage(state.names, state.rules, inherited, ctx.clients)} credentials={ctx.credentials} clients={ctx.clients} />
      <section aria-label="Options" className="grid gap-2">
        <h3 className="text-sm font-semibold">Options</h3>
        <dl className="grid grid-cols-1 gap-1 text-sm md:grid-cols-[200px_1fr] md:gap-x-4 md:gap-y-2">
          {ISSUANCE_FIELDS.filter((f) => f.key !== 'verificationRules').map((f) => {
            const e = effectiveOf(state.overrides, eff, f.key);
            return (
              <Fragment key={f.key}>
                <dt className="text-ink-muted">{f.label}</dt>
                <dd className="flex flex-wrap items-center gap-2">
                  {effectiveText(f, e, ctx)}
                  {!isUnset(f, e) && <SourceBadge source={e.source} />}
                </dd>
              </Fragment>
            );
          })}
        </dl>
      </section>
    </div>
  );
}
