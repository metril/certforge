import { Card, CardBody, CardHeader } from '@/components/Card';
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
    <div className="grid gap-4 pt-4 lg:grid-cols-2">
      <Card role="region" aria-labelledby="ov-names" className="content-start">
        <CardHeader title="Names" titleId="ov-names" />
        <CardBody className="grid gap-3">
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
        </CardBody>
      </Card>
      {/* Fix wave (Important): an unmanaged certificate's verificationRules
          is empty (uploaded (unmanaged) certificates never run the
          wizard), so Coverage would show a false "No matching rule" for
          every name on a certificate CertForge was never asked to verify
          at all. */}
      {cert.managed && (
        <Card>
          <CardBody>
            <CoveragePanel items={coverage(names, cert.verificationRules, inherited, ctx.clients)} credentials={ctx.credentials} clients={ctx.clients} />
          </CardBody>
        </Card>
      )}
      <Card role="region" aria-labelledby="ov-config" className="lg:col-span-2">
        <CardHeader title="Effective configuration" titleId="ov-config" />
        <CardBody>
          <EffectiveConfigList eff={eff} ctx={ctx} />
        </CardBody>
      </Card>
    </div>
  );
}
