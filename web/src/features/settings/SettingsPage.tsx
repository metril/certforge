import { Link } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { LATER } from '@/lib/nav';
import { IssuanceDefaultsSection } from './IssuanceDefaultsSection';
import { KekStatus } from './KekStatus';
import { OrgsList } from './OrgsList';
import { SchemaSection } from './SchemaSection';

export const SECTIONS = [
  { slug: 'general', label: 'General' },
  { slug: 'issuance-defaults', label: 'Issuance defaults' },
  { slug: 'backup', label: 'Backup and keys' },
] as const;
export type SectionSlug = (typeof SECTIONS)[number]['slug'];
const LATER_SECTIONS = ['Access', 'Authentication', 'Agents', 'Integrations'];

const item = 'flex h-9 items-center px-3 text-sm text-ink-muted hover:bg-subtle hover:text-ink';

export function SettingsPage({ section }: { section: SectionSlug }) {
  const current = SECTIONS.find((s) => s.slug === section)!;
  return (
    <>
      <PageHeader title="Settings" />
      <div className="grid gap-8 md:grid-cols-[200px_1fr]">
        <nav aria-label="Settings sections" className="grid content-start gap-0.5">
          {SECTIONS.map((s) => (
            <Link
              key={s.slug}
              to="/settings/$section"
              params={{ section: s.slug }}
              className={item}
              activeProps={{ className: 'bg-subtle font-semibold text-ink!', 'aria-current': 'page' }}
            >
              {s.label}
            </Link>
          ))}
          {LATER_SECTIONS.map((label) => (
            <Tooltip key={label}>
              <TooltipTrigger asChild>
                <span role="link" aria-disabled="true" tabIndex={0} className={`${item} cursor-not-allowed opacity-50`}>
                  {label}
                </span>
              </TooltipTrigger>
              <TooltipContent side="right">{LATER}</TooltipContent>
            </Tooltip>
          ))}
        </nav>
        <section aria-labelledby="settings-title" className="min-w-0">
          <h2 id="settings-title" className="mb-4 text-lg font-semibold">
            {current.label}
          </h2>
          {section === 'general' && (
            <>
              <SchemaSection section="general" />
              <OrgsList />
            </>
          )}
          {section === 'issuance-defaults' && <IssuanceDefaultsSection />}
          {section === 'backup' && (
            <>
              <KekStatus />
              <SchemaSection section="backup" />
            </>
          )}
        </section>
      </div>
    </>
  );
}
