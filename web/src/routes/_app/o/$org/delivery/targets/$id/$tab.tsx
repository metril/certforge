import { createFileRoute, redirect } from '@tanstack/react-router';
import { targetLoader } from '@/features/delivery/targetLoader';
import { TargetDetailPage } from '@/features/delivery/TargetPages';
import { targetDetailSearch } from '@/features/delivery/search';
import { TARGET_TABS, type TargetTab } from '@/features/delivery/tabs';

export const Route = createFileRoute('/_app/o/$org/delivery/targets/$id/$tab')({
  staticData: { ownHeader: true },
  validateSearch: targetDetailSearch,
  beforeLoad: ({ params }) => {
    if (!(TARGET_TABS as readonly string[]).includes(params.tab)) throw redirect({ to: '/o/$org/delivery/targets/$id/$tab', params: { ...params, tab: 'overview' } });
  },
  loader: (ctx) => targetLoader(ctx),
  component: function TargetRoute() {
    const { id, tab } = Route.useParams();
    const { open } = Route.useSearch();
    return <TargetDetailPage id={id} tab={tab as TargetTab} open={open} />;
  },
});
