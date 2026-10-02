import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { useLogout } from '@/api/queries/auth';
import { Card } from '@/components/Card';
import { Button } from '@/components/ui/button';

// Fix round 1 (review): a `Me` with no orgs used to redirect "/" into a
// thrown Error (a crash) rather than a real page, and the Sidebar built
// broken `/o//overview`-style links for it. This is the graceful landing
// spot: one sentence, one button (spec: "Empty states are one sentence
// plus one button").
function NoOrganization() {
  const logout = useLogout();
  const navigate = useNavigate();
  return (
    <Card className="grid place-items-center gap-4 py-20 text-center">
      <p className="text-sm text-ink-muted">No organization exists for your account yet.</p>
      <Button variant="outline" onClick={() => logout.mutate(undefined, { onSettled: () => void navigate({ to: '/login' }) })}>
        Sign out
      </Button>
    </Card>
  );
}

export const Route = createFileRoute('/_app/no-organization')({ component: NoOrganization });
