import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { CasPage } from '@/features/issuers/CasPage';

export const Route = createFileRoute('/_app/o/$org/issuers/cas')({
  validateSearch: z.object({ edit: z.string().optional().catch(undefined) }),
  component: CasPage,
});
