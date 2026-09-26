import { CircleAlert, FileDiff } from 'lucide-react';
import type { Client, DeploymentState } from '@/api/types';
import { DEPLOY_META } from '@/lib/clientStatus';
import { ToneChip } from './StatusChip';

export function DeploymentChip({ state, withHelp = false }: { state: DeploymentState; withHelp?: boolean }) {
  const m = DEPLOY_META[state];
  return <ToneChip tone={m.tone} icon={m.icon} label={m.label} help={withHelp ? m.help : undefined} />;
}

/** The clients list's Drift column: drift and failed counts as chips, or a muted 0. */
export function DeploymentCounts({ client }: { client: Pick<Client, 'driftCount' | 'failedCount'> }) {
  if (client.driftCount === 0 && client.failedCount === 0) return <span className="text-ink-muted tabular-nums">0</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {client.driftCount > 0 && <ToneChip tone="drift" icon={FileDiff} label={`${client.driftCount} drift`} />}
      {client.failedCount > 0 && <ToneChip tone="failed" icon={CircleAlert} label={`${client.failedCount} failed`} />}
    </span>
  );
}
