import { Fragment } from 'react';
import { Crown } from 'lucide-react';
import type { EffectiveMap } from '@/api/types';
import { effectiveText, ISSUANCE_FIELDS, type FieldCtx } from '@/features/settings/issuanceFields';
import { SourceBadge } from '@/forms/InheritableField';

// Fix round 1 (review, Important #1): OverviewTab and SettingsTab each had
// their own copy of this name chip and this effective-configuration list.
// Shared here so both tabs render the exact same markup.

/** A read-only name chip: the value plus a crown when it's the common name. */
export function NameChipStatic({ value, isCn }: { value: string; isCn: boolean }) {
  return (
    <li className="inline-flex h-7 items-center gap-1 rounded-sm border border-border px-2 font-mono text-xs">
      {value}
      {isCn && <Crown className="size-3.5 text-primary" aria-label="Common name" />}
    </li>
  );
}

/** The effective issuance configuration (every field but verificationRules,
 * shown elsewhere as coverage) with its source badge. Stacks to one column
 * below `md`, matching ReviewStep's own responsive `<dl>`. */
export function EffectiveConfigList({ eff, ctx }: { eff: EffectiveMap; ctx: FieldCtx }) {
  return (
    <dl className="grid grid-cols-1 gap-x-4 gap-y-2 text-sm md:grid-cols-[200px_1fr]">
      {ISSUANCE_FIELDS.filter((f) => f.key !== 'verificationRules').map((f) => {
        const e = eff[f.key] ?? { value: null, source: 'default' as const };
        return (
          <Fragment key={f.key}>
            <dt className="text-ink-muted">{f.label}</dt>
            <dd className="flex flex-wrap items-center gap-2">
              {effectiveText(f, e, ctx)}
              <SourceBadge source={e.source} />
            </dd>
          </Fragment>
        );
      })}
    </dl>
  );
}
