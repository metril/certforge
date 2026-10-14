import { createFileRoute } from '@tanstack/react-router';
import { NewTargetPage } from '@/features/delivery/TargetPages';

export const Route = createFileRoute('/_app/o/$org/delivery/targets/new')({ component: NewTargetPage });
