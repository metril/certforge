import { createFileRoute } from '@tanstack/react-router';
import { EnrolPage } from '@/features/clients/enrol/EnrolPage';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/clients/new')({ beforeLoad: ({ context }) => denyAllOrgs(context), component: EnrolPage });
