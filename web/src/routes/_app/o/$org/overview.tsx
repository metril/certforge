import { createFileRoute } from '@tanstack/react-router';
import { OverviewPage } from '@/features/overview/OverviewPage';
import { overviewSearch } from '@/features/overview/search';

export const Route = createFileRoute('/_app/o/$org/overview')({ validateSearch: overviewSearch, component: OverviewPage });
