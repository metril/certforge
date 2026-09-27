import { createFileRoute } from '@tanstack/react-router';
import { ImportPage } from '@/features/certificates/import/ImportPage';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/certificates/import')({
  beforeLoad: ({ context }) => denyAllOrgs(context),
  component: ImportPage,
});
