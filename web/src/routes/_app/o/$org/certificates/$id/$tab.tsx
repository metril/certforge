import { createFileRoute, redirect } from '@tanstack/react-router';
import { certificateQuery } from '@/api/queries/certificates';
import { CertificateDetail } from '@/features/certificates/detail/CertificateDetail';
import { TABS, type Tab } from '@/features/certificates/detail/tabs';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/certificates/$id/$tab')({
  beforeLoad: ({ context, params }) => {
    denyAllOrgs(context);
    if (!(TABS as readonly string[]).includes(params.tab)) {
      throw redirect({ to: '/o/$org/certificates/$id/$tab', params: { ...params, tab: 'overview' } });
    }
  },
  loader: ({ context: { queryClient, org }, params }) => queryClient.ensureQueryData(certificateQuery(org.id, params.id)),
  component: function CertificateRoute() {
    const { id, tab } = Route.useParams();
    return <CertificateDetail id={id} tab={tab as Tab} />;
  },
});
