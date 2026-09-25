import { Fragment } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Crown } from 'lucide-react';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { Certificate, EffectiveMap } from '@/api/types';
import { ISSUANCE_FIELDS, useFieldCtx } from '@/features/settings/issuanceFields';
import { CoveragePanel } from '@/forms/CoveragePanel';
import { SourceBadge } from '@/forms/InheritableField';
import { coverage, inheritedFrom } from '@/lib/coverage';
import { classifyName, groupByZone } from '@/lib/names';

export function OverviewTab({ cert, orgId }: { cert: Certificate; orgId: string }) {
  const ctx = useFieldCtx(orgId);
  const inherited = inheritedFrom(useQuery(effectiveDefaultsQuery(orgId)).data);
  const names = [...new Set([cert.commonName, ...cert.sans])];
  const groups = groupByZone(names.map(classifyName));
  const eff = (cert.effective ?? {}) as EffectiveMap;
  return (
    <div className="grid gap-8 pt-4 lg:grid-cols-2">
      <section aria-labelledby="ov-names" className="grid content-start gap-3">
        <h2 id="ov-names" className="text-base font-semibold">
          Names
        </h2>
        {groups.map((g) => (
          <div key={g.zone} className="grid gap-1">
            <h3 className="font-mono text-xs text-ink-muted">{g.zone}</h3>
            <ul className="flex flex-wrap gap-1.5">
              {g.names.map((n) => (
                <li key={n.value} className="inline-flex h-7 items-center gap-1 rounded-sm border border-border px-2 font-mono text-xs">
                  {n.value}
                  {n.value === cert.commonName && <Crown className="size-3.5 text-primary" aria-label="Common name" />}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </section>
      <CoveragePanel items={coverage(names, cert.verificationRules, inherited)} credentials={ctx.credentials} />
      <section aria-labelledby="ov-config" className="grid gap-2 lg:col-span-2">
        <h2 id="ov-config" className="text-base font-semibold">
          Effective configuration
        </h2>
        <dl className="grid grid-cols-[200px_1fr] gap-x-4 gap-y-2 text-sm">
          {ISSUANCE_FIELDS.filter((f) => f.key !== 'verificationRules').map((f) => {
            const e = eff[f.key] ?? { value: null, source: 'default' as const };
            return (
              <Fragment key={f.key}>
                <dt className="text-ink-muted">{f.label}</dt>
                <dd className="flex flex-wrap items-center gap-2">
                  {e.value === null || e.value === undefined ? 'Server default' : f.display(e.value, ctx)}
                  <SourceBadge source={e.source} />
                </dd>
              </Fragment>
            );
          })}
        </dl>
      </section>
    </div>
  );
}
