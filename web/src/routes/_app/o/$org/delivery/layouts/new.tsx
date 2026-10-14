import { createFileRoute } from '@tanstack/react-router';
import { NewLayoutPage } from '@/features/delivery/LayoutPages';

export const Route = createFileRoute('/_app/o/$org/delivery/layouts/new')({ staticData: { ownHeader: true }, component: NewLayoutPage });
