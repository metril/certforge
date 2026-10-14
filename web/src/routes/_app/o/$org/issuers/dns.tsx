import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { CredentialsPage } from '@/features/issuers/CredentialsPage';

export const Route = createFileRoute('/_app/o/$org/issuers/dns')({
  // `?edit=<id>` opens that credential's sheet (entity links).
  validateSearch: z.object({ edit: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined) }),
  component: CredentialsPage,
});
