import { createFileRoute } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';

export const Route = createFileRoute('/_app/o/$org/overview')({ component: () => <PageHeader title="Overview" /> });
