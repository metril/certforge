import { createFileRoute } from '@tanstack/react-router';
import { UploadPage } from '@/features/certificates/upload/UploadPage';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/certificates/upload')({
  beforeLoad: ({ context }) => denyAllOrgs(context),
  component: UploadPage,
});
