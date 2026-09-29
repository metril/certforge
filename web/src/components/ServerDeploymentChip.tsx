import { CircleCheck, CircleX, Clock, type LucideIcon } from 'lucide-react';
import type { ServerDeploymentStatus } from '@/api/types';
import type { Tone } from '@/lib/status';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { ToneChip } from './StatusChip';

// UI conventions (5B plan): pending -> Clock "Pending", deployed -> CircleCheck
// "Deployed", failed -> CircleX "Failed", with lastError as the failed chip's
// own tooltip (distinct from the withHelp tooltip, which explains the states
// in general via serverDeployment.status).
const META: Record<ServerDeploymentStatus, { label: string; tone: Tone; icon: LucideIcon }> = {
  pending: { label: 'Pending', tone: 'pending', icon: Clock },
  deployed: { label: 'Deployed', tone: 'valid', icon: CircleCheck },
  failed: { label: 'Failed', tone: 'failed', icon: CircleX },
};

/** A server-side deploy target's own deployment state (Grant.serverDeployment),
 * distinct from DeploymentChip (Grant.deployment, agent-side). */
export function ServerDeploymentChip({ status, lastError, withHelp = false }: { status: ServerDeploymentStatus; lastError?: string | null; withHelp?: boolean }) {
  const m = META[status];
  const chip = <ToneChip tone={m.tone} icon={m.icon} label={m.label} help={withHelp ? 'serverDeployment.status' : undefined} />;
  if (status !== 'failed' || !lastError) return chip;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{chip}</TooltipTrigger>
      <TooltipContent>{lastError}</TooltipContent>
    </Tooltip>
  );
}
