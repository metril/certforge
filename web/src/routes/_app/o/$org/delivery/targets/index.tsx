import { createFileRoute } from '@tanstack/react-router';
import { TargetsPage } from '@/features/delivery/TargetsPage';

export const Route = createFileRoute('/_app/o/$org/delivery/targets/')({ component: TargetsPage });
