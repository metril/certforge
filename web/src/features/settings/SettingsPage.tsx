import { Link } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { useMe } from '@/lib/org';
import { canAnywhere } from '@/lib/permissions';
import { AccessPage } from './access/AccessPage';
import { AgentsSection } from './agents/AgentsSection';
import { AuthenticationSection } from './AuthenticationSection';
import { BackupSection } from './BackupSection';
import { EncryptionKeyCard } from './EncryptionKeyCard';
import { IntegrationsSection } from './IntegrationsSection';
import { IssuanceDefaultsSection } from './IssuanceDefaultsSection';
import { OrgsList } from './OrgsList';
import { SchemaSection } from './SchemaSection';
import { SECTIONS, type SectionSlug } from './sections';

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
          {section === 'integrations' && <IntegrationsSection />}
          {section === 'backup' && (
            <>
              <EncryptionKeyCard />
              <BackupSection />
            </>
          )}
        </section>
      </div>
    </>
  );
}
