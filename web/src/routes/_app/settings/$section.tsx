import { createFileRoute } from '@tanstack/react-router';
import { PageHeader } from '@/components/PageHeader';

export const Route = createFileRoute('/_app/settings/$section')({ component: () => <PageHeader title="Settings" /> });
