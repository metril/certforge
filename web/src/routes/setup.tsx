import { createFileRoute, redirect } from '@tanstack/react-router';
import { setupStatusQuery } from '@/api/queries/auth';
import { SetupWizard } from '@/features/setup/SetupWizard';

export const Route = createFileRoute('/setup')({
  beforeLoad: async ({ context }) => {
    const status = await context.queryClient.ensureQueryData(setupStatusQuery);
    if (!status.needsSetup) throw redirect({ to: '/' });
  },
  component: SetupWizard,
});
