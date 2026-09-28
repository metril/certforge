import { useQuery } from '@tanstack/react-query';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { Certificate, EffectiveMap } from '@/api/types';
import { useFieldCtx } from '@/features/settings/issuanceFields';
import { CoveragePanel } from '@/forms/CoveragePanel';
import { coverage, inheritedFrom } from '@/lib/coverage';
import { classifyName, groupByZone } from '@/lib/names';
import { EffectiveConfigList, NameChipStatic } from './shared';

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
                <NameChipStatic key={n.value} value={n.value} isCn={n.value === cert.commonName} />
              ))}
            </ul>
          </div>
        ))}
      </section>
      {/* Fix wave (Important): an unmanaged certificate's verificationRules
          is empty (uploaded (unmanaged) certificates never run the
          wizard), so Coverage would show a false "No matching rule" for
          every name on a certificate CertForge was never asked to verify
          at all. */}
      {cert.managed && <CoveragePanel items={coverage(names, cert.verificationRules, inherited, ctx.clients)} credentials={ctx.credentials} clients={ctx.clients} />}
      <section aria-labelledby="ov-config" className="grid gap-2 lg:col-span-2">
        <h2 id="ov-config" className="text-base font-semibold">
          Effective configuration
        </h2>
        <EffectiveConfigList eff={eff} ctx={ctx} />
      </section>
    </div>
  );
}
