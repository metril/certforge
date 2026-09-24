import { createFileRoute } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';

export const Route = createFileRoute('/_app/o/$org/certificates/')({ component: () => <PageHeader title="Certificates" /> });
