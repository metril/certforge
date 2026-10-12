import { CircleCheck, CircleX, TriangleAlert } from 'lucide-react';
import type { AdcsProbeTemplate, AdcsTemplateRequirement } from '@/api/types';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { KEY_TYPES } from '@/features/settings/issuanceFields';

function Row({ r }: { r: AdcsTemplateRequirement }) {
  const Icon = r.ok ? CircleCheck : r.blocking ? CircleX : TriangleAlert;
  const tone = r.ok ? 'text-valid' : r.blocking ? 'text-failed' : 'text-expiring';
  return (
    <li className="grid gap-0.5">
      <div className="flex items-center gap-1.5">
        <Icon className={`size-3.5 shrink-0 ${tone}`} aria-hidden />
        <Tooltip>
          <TooltipTrigger asChild>
            <span tabIndex={0} className="cursor-default">
              {r.label}
              <span className="sr-only">{r.ok ? ' (met)' : r.blocking ? ' (not met, blocks use)' : ' (not met)'}</span>
            </span>
          </TooltipTrigger>
          <TooltipContent>{r.fix}</TooltipContent>
        </Tooltip>
      </div>
      {!r.ok && <p className="pl-5 text-ink-muted">{r.fix}</p>}
    </li>
  );
}

/** What the picked template needs and whether it gets it, plus the key types CertForge can issue with it. */
export function AdcsTemplateRequirements({ template }: { template: AdcsProbeTemplate }) {
  const labels = template.allowedKeyTypes.map((k) => KEY_TYPES.find((o) => o.value === k)?.label ?? k);
  return (
    <section aria-label={`Requirements for ${template.name}`} className="grid gap-1.5 rounded-md border border-border bg-subtle p-2 text-xs">
      <ul className="grid gap-1">
        {template.requirements.map((r) => (
          <Row key={r.key} r={r} />
        ))}
      </ul>
      <p className="text-ink-muted">CertForge key types: {labels.length > 0 ? labels.join(', ') : 'unknown'}</p>
    </section>
  );
}
