import { createFileRoute } from '@tanstack/react-router';
import { EnrollPage } from '@/features/clients/enroll/EnrollPage';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/clients/new')({ beforeLoad: ({ context }) => denyAllOrgs(context), component: EnrollPage });
