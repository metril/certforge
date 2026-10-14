import { createFileRoute, redirect } from '@tanstack/react-router';
import { CaDetailPage } from '@/features/issuers/CaDetailPage';
import type { CaTab } from '@/features/issuers/CaDetail';

export const Route = createFileRoute('/_app/o/$org/issuers/cas/$id/$tab')({
  staticData: { ownHeader: true },
  beforeLoad: ({ params }) => {
    if (params.tab !== 'overview' && params.tab !== 'crl') throw redirect({ to: '/o/$org/issuers/cas/$id/$tab', params: { ...params, tab: 'overview' } });
  },
  component: function CaRoute() {
    const { id, tab } = Route.useParams();
    return <CaDetailPage id={id} tab={tab as CaTab} />;
  },
});
