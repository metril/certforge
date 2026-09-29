import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { ChannelsPage } from '@/features/alerts/ChannelsPage';

export const Route = createFileRoute('/_app/o/$org/alerts/channels')({
  validateSearch: z.object({
    // Detail/create sheet (task 3): `edit=new` or an existing channel id.
    edit: z.string().optional().catch(undefined),
  }),
  component: ChannelsPage,
});
