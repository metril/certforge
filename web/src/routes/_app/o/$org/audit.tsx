import { createFileRoute } from '@tanstack/react-router';
import { AuditPage } from '@/features/audit/AuditPage';
import { auditSearch } from '@/features/audit/search';

export const Route = createFileRoute('/_app/o/$org/audit')({ validateSearch: auditSearch, component: AuditPage });
