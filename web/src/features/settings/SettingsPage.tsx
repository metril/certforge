import { lazy, Suspense } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';
import { useMe } from '@/lib/org';
import { canAnywhere } from '@/lib/permissions';
import { OrgsList } from './OrgsList';
import { SECTIONS, type SectionSlug } from './sections';

// Each section loads on demand: SchemaSection and the integrations/backup
// sections pull in @rjsf (SchemaForm), which only some sections need.
const AccessPage = lazy(() => import('./access/AccessPage').then((m) => ({ default: m.AccessPage })));
const AgentsSection = lazy(() => import('./agents/AgentsSection').then((m) => ({ default: m.AgentsSection })));
const AuthenticationSection = lazy(() => import('./AuthenticationSection').then((m) => ({ default: m.AuthenticationSection })));
const BackupSection = lazy(() => import('./BackupSection').then((m) => ({ default: m.BackupSection })));
const EncryptionKeyCard = lazy(() => import('./EncryptionKeyCard').then((m) => ({ default: m.EncryptionKeyCard })));
const IntegrationsSection = lazy(() => import('./IntegrationsSection').then((m) => ({ default: m.IntegrationsSection })));
const IssuanceDefaultsSection = lazy(() => import('./IssuanceDefaultsSection').then((m) => ({ default: m.IssuanceDefaultsSection })));
const SchemaSection = lazy(() => import('./SchemaSection').then((m) => ({ default: m.SchemaSection })));

function SectionSkeleton() {
  return (
    <div role="status" aria-label="Loading section" className="grid max-w-[720px] gap-3 rounded-md border border-border bg-panel p-4">
      <div className="h-4 w-40 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-2/3 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-1/2 animate-pulse rounded-sm bg-subtle" />
    </div>
  );
}

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
          <Suspense fallback={<SectionSkeleton />}>
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
              <div className="grid gap-4">
                <BackupSection />
                <EncryptionKeyCard />
              </div>
            )}
          </Suspense>
        </section>
      </div>
    </>
  );
}
