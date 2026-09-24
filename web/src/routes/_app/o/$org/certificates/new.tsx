import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { certificateQuery } from '@/api/queries/certificates';
import { CertificateWizard } from '@/features/certificates/wizard/CertificateWizard';

export const Route = createFileRoute('/_app/o/$org/certificates/new')({
  validateSearch: z.object({ from: z.string().optional().catch(undefined) }),
  loaderDeps: ({ search }) => ({ from: search.from }),
  loader: ({ context: { queryClient, org }, deps }) => (deps.from ? queryClient.ensureQueryData(certificateQuery(org.id, deps.from)) : undefined),
  component: function NewCertificateRoute() {
    const from = Route.useLoaderData();
    return <CertificateWizard key={from?.id ?? 'new'} from={from} />;
  },
});
