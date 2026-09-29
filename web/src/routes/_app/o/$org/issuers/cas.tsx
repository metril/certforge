import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { CasPage } from '@/features/issuers/CasPage';

const caType = z.enum(['acme', 'localca', 'vaultpki']);

export const Route = createFileRoute('/_app/o/$org/issuers/cas')({
  validateSearch: z.object({
    edit: z.string().optional().catch(undefined),
    // Detail sheet for a private CA (task 3); a plain string id like `edit`.
    view: z.string().optional().catch(undefined),
    // Initial Type for a new CA (`?edit=new&kind=localca`), e.g. from the
    // command palette or the Add CA button under an active filter.
    kind: caType.optional().catch(undefined),
    // Type filter for the table (`?type=`); absent means every kind.
    type: caType.optional().catch(undefined),
  }),
  component: CasPage,
});
