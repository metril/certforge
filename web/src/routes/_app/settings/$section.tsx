import { createFileRoute, notFound } from '@tanstack/react-router';
import { SettingsPage } from '@/features/settings/SettingsPage';
// Kept separate from SettingsPage.tsx (Task 14 fix) so `beforeLoad` below
// doesn't force the whole settings page module — and tldts along with it —
// into this route's eager half; see sections.ts's own comment.
import { SECTIONS, settingsSearch, type SectionSlug } from '@/features/settings/sections';

export const Route = createFileRoute('/_app/settings/$section')({
  validateSearch: settingsSearch,
  beforeLoad: ({ params }) => {
    if (!SECTIONS.some((s) => s.slug === params.section)) throw notFound();
  },
  component: function SettingsRoute() {
    const { section } = Route.useParams();
    return <SettingsPage section={section as SectionSlug} />;
  },
});
