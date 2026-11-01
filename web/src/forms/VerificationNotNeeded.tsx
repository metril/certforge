import { CircleMinus } from 'lucide-react';
import { ToneChip } from '@/components/StatusChip';

/** Shown in place of CoveragePanel when the effective CA is private: it
 * issues without domain verification, so coverage warnings would mislead. */
export function VerificationNotNeeded({ caName }: { caName?: string }) {
  return (
    <section aria-label="Verification" className="flex flex-wrap items-center gap-2 text-sm">
      <ToneChip tone="neutral" icon={CircleMinus} label="Not needed" />
      <span className="text-ink-muted">{caName ?? 'This CA'} issues without domain verification</span>
    </section>
  );
}
