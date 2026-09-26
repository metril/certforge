import { CircleAlert, CircleCheck, CircleHelp, CircleX, FileDiff, type LucideIcon } from 'lucide-react';
import type { Deployment } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { ToneChip } from '@/components/StatusChip';
import { fileRows, shortHash, type FileRow } from '@/lib/clientStatus';
import type { Tone } from '@/lib/status';

const MATCH: Record<FileRow['match'], { label: string; tone: Tone; icon: LucideIcon }> = {
  ok: { label: 'Match', tone: 'valid', icon: CircleCheck },
  changed: { label: 'Changed', tone: 'drift', icon: FileDiff },
  missing: { label: 'Missing', tone: 'failed', icon: CircleX },
  unexpected: { label: 'Unexpected', tone: 'neutral', icon: CircleHelp },
};

/** Expected (server-rendered) against installed (agent-reported) digests. */
export function FileCompare({ deployment, name }: { deployment: Deployment; name: string }) {
  const reported = deployment.reportedAt !== null;
  const rows = fileRows(deployment);
  return (
    <div className="grid min-w-0 gap-2">
      <div className="flex items-center gap-1.5 text-xs text-ink-muted">
        Expected and installed files <HelpTip id="grant.files" />
      </div>
      {deployment.error && (
        <p className="flex items-start gap-1.5 break-all font-mono text-xs">
          <CircleAlert className="mt-0.5 size-3.5 shrink-0 text-failed" aria-hidden />
          {deployment.error}
        </p>
      )}
      {!reported && <p className="text-sm text-ink-muted">Not reported yet.</p>}
      <ul aria-label={`Files for ${name}`} className="grid">
        {rows.map((r) => {
          const m = MATCH[r.match];
          return (
            <li key={r.path} className="grid gap-1 border-b border-border py-1.5 text-xs last:border-0 md:grid-cols-[minmax(0,1fr)_120px_120px_auto] md:items-center md:gap-3">
              <span className="min-w-0 truncate font-mono" title={r.path}>
                {r.path}
              </span>
              <span className="font-mono text-ink-muted" title={r.expected ?? undefined}>
                <span className="md:sr-only">Expected </span>
                <span>{shortHash(r.expected)}</span>
              </span>
              <span className="font-mono text-ink-muted" title={r.installed ?? undefined}>
                <span className="md:sr-only">Installed </span>
                <span>{shortHash(r.installed)}</span>
              </span>
              {reported && <ToneChip tone={m.tone} icon={m.icon} label={m.label} />}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
