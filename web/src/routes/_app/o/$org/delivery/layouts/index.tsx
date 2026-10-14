import { createFileRoute } from '@tanstack/react-router';
import { LayoutsPage } from '@/features/delivery/LayoutsPage';

export const Route = createFileRoute('/_app/o/$org/delivery/layouts/')({ component: LayoutsPage });
