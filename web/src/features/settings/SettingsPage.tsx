import { Link } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useMe } from '@/lib/org';
import { LATER } from '@/lib/nav';
import { canAnywhere } from '@/lib/permissions';
import { AccessPage } from './access/AccessPage';
import { AgentsSection } from './agents/AgentsSection';
import { AuthenticationSection } from './AuthenticationSection';
import { IssuanceDefaultsSection } from './IssuanceDefaultsSection';
import { KekStatus } from './KekStatus';
import { OrgsList } from './OrgsList';
import { SchemaSection } from './SchemaSection';
import { SECTIONS, type SectionSlug } from './sections';

const LATER_SECTIONS = ['Integrations'];

const item = 'flex h-9 items-center px-3 text-sm text-ink-muted hover:bg-subtle hover:text-ink';

export function SettingsPage({ section }: { section: SectionSlug }) {
  const me = useMe();
  const current = SECTIONS.find((s) => s.slug === section)!;
  // Controller ruling (D5): the Access section is visible only to callers
  // with users:read anywhere; AccessPage itself also guards this, this just
  // keeps the nav link from being offered at all.
  const visibleSections = SECTIONS.filter((s) => s.slug !== 'access' || canAnywhere(me, 'users:read'));
  return (
    <>
      <PageHeader title="Settings" />
      <div className="grid gap-8 md:grid-cols-[200px_1fr]">
        <nav aria-label="Settings sections" className="grid content-start gap-0.5">
          {visibleSections.map((s) => (
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
          {section === 'access' && <AccessPage />}
          {section === 'authentication' && <AuthenticationSection />}
          {section === 'issuance-defaults' && <IssuanceDefaultsSection />}
          {section === 'agents' && <AgentsSection />}
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
