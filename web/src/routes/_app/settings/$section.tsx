import { createFileRoute, notFound } from '@tanstack/react-router';
import { SECTIONS, SettingsPage, type SectionSlug } from '@/features/settings/SettingsPage';

export const Route = createFileRoute('/_app/settings/$section')({
  beforeLoad: ({ params }) => {
    if (!SECTIONS.some((s) => s.slug === params.section)) throw notFound();
  },
  component: function SettingsRoute() {
    const { section } = Route.useParams();
    return <SettingsPage section={section as SectionSlug} />;
  },
});
