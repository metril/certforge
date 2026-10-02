import { createFileRoute } from '@tanstack/react-router';
import { FlowPage } from '@/features/flow/FlowPage';
import { flowSearch } from '@/features/flow/search';
import { denyAllOrgs } from '@/lib/org';

export const Route = createFileRoute('/_app/o/$org/flow')({
  validateSearch: flowSearch,
  beforeLoad: ({ context }) => denyAllOrgs(context),
  component: FlowPage,
});
