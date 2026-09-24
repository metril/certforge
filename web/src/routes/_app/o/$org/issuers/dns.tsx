import { createFileRoute } from '@tanstack/react-router';
import { CredentialsPage } from '@/features/issuers/CredentialsPage';

export const Route = createFileRoute('/_app/o/$org/issuers/dns')({ component: CredentialsPage });
