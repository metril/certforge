import { createFileRoute } from '@tanstack/react-router';
import { AccountsPage } from '@/features/issuers/AccountsPage';

export const Route = createFileRoute('/_app/o/$org/issuers/accounts')({ component: AccountsPage });
