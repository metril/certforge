import { Fragment } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Crown, Pencil } from 'lucide-react';
import { effectiveDefaultsQuery } from '@/api/queries/defaults';
import type { Certificate, EffectiveMap } from '@/api/types';
import { Button } from '@/components/ui/button';
import { ISSUANCE_FIELDS, rulesSummary, useFieldCtx } from '@/features/settings/issuanceFields';
import { CoveragePanel } from '@/forms/CoveragePanel';
import { SourceBadge } from '@/forms/InheritableField';
import { coverage, inheritedFrom } from '@/lib/coverage';

type Props = { cert: Certificate; orgId: string; orgSlug: string };

// Controller ruling: this tab is read-only — the certificate's configuration
// rendered as the wizard's own sections (names, verification rules plus
// coverage, options with their SourceBadge sources) — with a single Edit
// link into the existing wizard edit route (Task 14,
// /o/$org/certificates/$id/edit), not a second editable form with its own
// PUT flow.
export function SettingsTab({ cert, orgId, orgSlug }: Props) {
  const ctx = useFieldCtx(orgId);
  const inherited = inheritedFrom(useQuery(effectiveDefaultsQuery(orgId)).data);
  const names = [...new Set([cert.commonName, ...cert.sans])];
  const eff = (cert.effective ?? {}) as EffectiveMap;
  return (
    <div className="grid gap-8 pt-4">
      <div className="flex justify-end">
        <Button asChild variant="outline">
          <Link to="/o/$org/certificates/$id/edit" params={{ org: orgSlug, id: cert.id }}>
            <Pencil className="size-4" aria-hidden />
            Edit
          </Link>
        </Button>
      </div>
      <section aria-labelledby="st-names" className="grid gap-2">
        <h2 id="st-names" className="text-base font-semibold">
          Names
        </h2>
        <ul className="flex flex-wrap gap-1.5">
          {names.map((n) => (
            <li key={n} className="inline-flex h-7 items-center gap-1 rounded-sm border border-border px-2 font-mono text-xs">
              {n}
              {n === cert.commonName && <Crown className="size-3.5 text-primary" aria-label="Common name" />}
            </li>
          ))}
        </ul>
      </section>
      <section aria-labelledby="st-verification" className="grid gap-3">
        <h2 id="st-verification" className="text-base font-semibold">
          Verification
        </h2>
        <p className="text-sm">{rulesSummary(cert.verificationRules, ctx.credentials)}</p>
        <CoveragePanel items={coverage(names, cert.verificationRules, inherited)} credentials={ctx.credentials} />
      </section>
      <section aria-labelledby="st-options" className="grid gap-2">
        <h2 id="st-options" className="text-base font-semibold">
          Options
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
