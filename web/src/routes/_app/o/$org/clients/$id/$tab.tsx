import { createFileRoute, redirect } from '@tanstack/react-router';
import { clientQuery } from '@/api/queries/clients';
import { sitesQuery } from '@/api/queries/sites';
import { ClientDetail } from '@/features/clients/detail/ClientDetail';
import { clientDetailSearch } from '@/features/clients/detail/search';
import { CLIENT_TABS, DEFAULT_CLIENT_TAB, type ClientTab } from '@/features/clients/detail/tabs';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/clients/$id/$tab')({
  validateSearch: clientDetailSearch,
  beforeLoad: ({ context, params }) => {
    denyAllOrgs(context);
    if (!(CLIENT_TABS as readonly string[]).includes(params.tab)) {
      throw redirect({ to: '/o/$org/clients/$id/$tab', params: { ...params, tab: DEFAULT_CLIENT_TAB } });
    }
  },
  loader: ({ context: { queryClient, org }, params }) =>
    Promise.all([queryClient.ensureQueryData(clientQuery(org.id, params.id)), queryClient.ensureQueryData(sitesQuery(org.id))]),
  component: function ClientRoute() {
    const { id, tab } = Route.useParams();
    return <ClientDetail id={id} tab={tab as ClientTab} />;
  },
});
