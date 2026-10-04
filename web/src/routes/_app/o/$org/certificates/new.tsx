import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { certificateQuery } from '@/api/queries/certificates';
import { CertificateWizard } from '@/features/certificates/wizard/CertificateWizard';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/certificates/new')({
  beforeLoad: ({ context }) => denyAllOrgs(context),
  validateSearch: z.object({ from: z.string().optional().catch(undefined) }),
  loaderDeps: ({ search }) => ({ from: search.from }),
  loader: ({ context: { queryClient, org }, deps }) => (deps.from ? queryClient.fetchQuery(certificateQuery(org.id, deps.from)) : undefined),
  component: function NewCertificateRoute() {
    const from = Route.useLoaderData();
    return <CertificateWizard key={from?.id ?? 'new'} from={from} />;
  },
});
