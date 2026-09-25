import { Lock } from 'lucide-react';
import { HelpTip } from './HelpTip';

export function ReadOnlyBanner() {
  return (
    <div role="status" aria-label="Read-only view" className="mb-4 flex h-8 items-center gap-2 border-b border-border text-sm text-ink-muted">
      <Lock className="size-4" aria-hidden />
      All orgs · read-only
      <HelpTip id="orgs.allOrgs" />
    </div>
  );
}
