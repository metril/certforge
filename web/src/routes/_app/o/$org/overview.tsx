import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/_app/o/$org/overview')({
  component: () => <h1 className="p-8 text-xl font-semibold">Overview</h1>,
});
