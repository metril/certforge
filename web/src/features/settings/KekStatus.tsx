import { useQuery } from '@tanstack/react-query';
import { CircleAlert, CircleCheck, CircleX } from 'lucide-react';
import { readinessQuery } from '@/api/queries/health';
import { HelpTip } from '@/components/HelpTip';
import { ToneChip } from '@/components/StatusChip';

/** Adaptation (preflight A7, controller ruling): the backup settings schema
 * dropped `kekProvider` (only `kekEscrowConfirmed` remains), so the key
 * status shown here comes from GET /readyz's `checks.kek` instead —
 * matching the same check the setup wizard gates on. */
export function KekStatus() {
  const q = useQuery(readinessQuery);
  const kek = q.data?.checks.find((c) => c.name === 'kek');
  const label = kek?.ok ? 'OK' : 'Failed';
  // Review fix round 1 (#7): fetchReadiness maps a plain "failed" check
  // string to both the ok:false tone/label AND kek.message verbatim, so
  // showing both said "Failed" twice; only show the message when it adds
  // something the chip word doesn't already say.
  const extra = kek?.message && kek.message.toLowerCase() !== label.toLowerCase() ? kek.message : null;

  return (
    <div className="mb-4 flex items-center gap-2">
      <span className="text-sm font-semibold">Encryption key</span>
      <HelpTip id="backup.kek" />
      {q.isPending || !kek ? (
        <span className="text-sm text-ink-muted">{q.isPending ? 'Checking…' : 'Unknown'}</span>
      ) : (
        <ToneChip tone={kek.ok ? 'valid' : 'failed'} icon={kek.ok ? CircleCheck : CircleX} label={label} />
      )}
      {extra && <span className="text-xs text-ink-muted">{extra}</span>}
      {q.isError && (
        <span className="flex items-center gap-1 text-xs">
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          Could not check readiness
        </span>
      )}
    </div>
  );
}
