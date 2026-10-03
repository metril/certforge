import { Lock } from 'lucide-react';

/** Top-of-sheet notice for a viewer without write access: every field below
 * is disabled, and this says why. */
export function ReadOnlyNotice({ reason }: { reason: string }) {
  return (
    <p role="status" className="flex items-center gap-1.5 rounded-md border border-border bg-subtle px-3 py-2 text-sm text-ink-muted">
      <Lock className="size-3.5 shrink-0" aria-hidden />
      Read-only: {reason}.
    </p>
  );
}
