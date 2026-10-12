import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { CredentialsPage } from '@/features/delivery/CredentialsPage';

export const Route = createFileRoute('/_app/o/$org/delivery/credentials')({
  validateSearch: z.object({ edit: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined) }),
  component: CredentialsPage,
});
