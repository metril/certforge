import { createFileRoute, redirect } from '@tanstack/react-router';
import { certificateQuery } from '@/api/queries/certificates';
import { CertificateWizard } from '@/features/certificates/wizard/CertificateWizard';
import { denyAllOrgs } from '@/lib/org';

// Adaptation (controller ruling, docs/design.md "Certificate create
// wizard"): a dedicated edit route reusing the wizard, loaded via
// `fromCertificate` and saved with PUT (name changes reissue). Not in the
// Task 14 brief's file list, which covers create/duplicate only.
//
// Task 7: an unmanaged certificate can't be edited here (the server 409s on
// update) — sending its own overview tab instead of rendering a wizard the
// caller can fill in and never submit.
export const Route = createFileRoute('/_app/o/$org/certificates/$id/edit')({
  beforeLoad: ({ context }) => denyAllOrgs(context),
  loader: async ({ context: { queryClient, org }, params }) => {
    const cert = await queryClient.ensureQueryData(certificateQuery(org.id, params.id));
    if (!cert.managed) throw redirect({ to: '/o/$org/certificates/$id/$tab', params: { org: org.slug, id: params.id, tab: 'overview' } });
    return cert;
  },
  component: function EditCertificateRoute() {
    const cert = Route.useLoaderData();
    return <CertificateWizard key={cert.id} edit={cert} />;
  },
});
