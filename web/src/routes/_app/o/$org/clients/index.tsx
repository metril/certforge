import { createFileRoute } from '@tanstack/react-router';
import { ClientsPage } from '@/features/clients/list/ClientsPage';
import { clientListSearch } from '@/features/clients/list/search';

export const Route = createFileRoute('/_app/o/$org/clients/')({ validateSearch: clientListSearch, component: ClientsPage });
