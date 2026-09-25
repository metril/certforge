import { createFileRoute } from '@tanstack/react-router';
import { certificateQuery } from '@/api/queries/certificates';
import { CertificateWizard } from '@/features/certificates/wizard/CertificateWizard';
import { denyAllOrgs } from '@/lib/org';

// Adaptation (controller ruling, docs/design.md "Certificate create
// wizard"): a dedicated edit route reusing the wizard, loaded via
// `fromCertificate` and saved with PUT (name changes reissue). Not in the
// Task 14 brief's file list, which covers create/duplicate only.
export const Route = createFileRoute('/_app/o/$org/certificates/$id/edit')({
  beforeLoad: ({ context }) => denyAllOrgs(context),
  loader: ({ context: { queryClient, org }, params }) => queryClient.ensureQueryData(certificateQuery(org.id, params.id)),
  component: function EditCertificateRoute() {
    const cert = Route.useLoaderData();
    return <CertificateWizard key={cert.id} edit={cert} />;
  },
});
