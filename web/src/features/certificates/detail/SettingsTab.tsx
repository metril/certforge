import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Pencil } from 'lucide-react';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { Certificate, EffectiveMap } from '@/api/types';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { rulesSummary, useFieldCtx } from '@/features/settings/issuanceFields';
import { CoveragePanel } from '@/forms/CoveragePanel';
import { coverage, inheritedFrom } from '@/lib/coverage';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { EffectiveConfigList, NameChipStatic } from './shared';

type Props = { cert: Certificate; orgId: string; orgSlug: string };

// Controller ruling: this tab is read-only — the certificate's configuration
// rendered as the wizard's own sections (names, verification rules plus
// coverage, options with their SourceBadge sources) — with a single Edit
// link into the existing wizard edit route (Task 14,
// /o/$org/certificates/$id/edit), not a second editable form with its own
// PUT flow.
export function SettingsTab({ cert, orgId, orgSlug }: Props) {
  const me = useMe();
  const canEdit = can(me, 'certs:write', orgId);
  const ctx = useFieldCtx(orgId);
  const inherited = inheritedFrom(useQuery(effectiveDefaultsQuery(orgId)).data);
  const names = [...new Set([cert.commonName, ...cert.sans])];
  const eff = (cert.effective ?? {}) as EffectiveMap;
  return (
    <div className="grid gap-8 pt-4">
      <div className="flex justify-end">
        {canEdit ? (
          <Button asChild variant="outline">
            <Link to="/o/$org/certificates/$id/edit" params={{ org: orgSlug, id: cert.id }}>
              <Pencil className="size-4" aria-hidden />
              Edit
            </Link>
          </Button>
        ) : (
          <PermissionTip allowed={false} action="certs:write">
            <Button variant="outline" disabled>
              <Pencil className="size-4" aria-hidden />
              Edit
            </Button>
          </PermissionTip>
        )}
      </div>
      <section aria-labelledby="st-names" className="grid gap-2">
        <h2 id="st-names" className="text-base font-semibold">
          Names
        </h2>
        <ul className="flex flex-wrap gap-1.5">
          {names.map((n) => (
            <NameChipStatic key={n} value={n} isCn={n === cert.commonName} />
          ))}
        </ul>
      </section>
      <section aria-labelledby="st-verification" className="grid gap-3">
        <h2 id="st-verification" className="text-base font-semibold">
          Verification
        </h2>
        <p className="text-sm">{rulesSummary(cert.verificationRules, ctx.credentials, ctx.clients)}</p>
        <CoveragePanel items={coverage(names, cert.verificationRules, inherited)} credentials={ctx.credentials} clients={ctx.clients} />
      </section>
      <section aria-labelledby="st-options" className="grid gap-2">
        <h2 id="st-options" className="text-base font-semibold">
          Options
        </h2>
        <EffectiveConfigList eff={eff} ctx={ctx} />
      </section>
    </div>
  );
}
